// 📦 Import web framework for building REST API
use actix_web::{web, App, HttpResponse, HttpServer, Responder};

// 📦 Import base64 encoding/decoding
use base64::{engine::general_purpose, Engine as _};

// 📦 Import Kyber512 (quantum-safe key encapsulation)
use pqcrypto_kyber::kyber512;

// 📦 Import Falcon512 (quantum-safe digital signatures)
use pqcrypto_falcon::falcon512;

// 📦 Import JSON serialization/deserialization
use serde::{Deserialize, Serialize};

// 📦 Import trait methods for PQ crypto
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait,
    PublicKey as KemPublicKeyTrait,
    SecretKey as KemSecretKeyTrait,
    SharedSecret as KemSharedSecretTrait,
};
use pqcrypto_traits::sign::{
    DetachedSignature as SigDetachedTrait,
    PublicKey as SigPublicKeyTrait,
    SecretKey as SigSecretKeyTrait,
};

// 📦 Import ECDSA (classical cryptography)
use secp256k1::{Secp256k1, Message, SecretKey as EcdsaSecretKey, PublicKey as EcdsaPublicKey};
use sha2::{Sha256, Digest};

// 📦 Import random number generator

// 📦 Import for timestamp generation
use std::time::{SystemTime, UNIX_EPOCH};

// -----------------------------------------------------------------------------
// DATA STRUCTURES
// -----------------------------------------------------------------------------

// 👤 Represents a user's key material (HYBRID: ECDSA + Falcon + Kyber)
#[derive(Clone)]
struct UserKeys {
    name: String,
    
    // ========================
    // CLASSICAL KEYS (ECDSA)
    // ========================
    ecdsa_sk: Vec<u8>,  // SECRET: ECDSA private key (32 bytes)
    ecdsa_pk: Vec<u8>,  // PUBLIC: ECDSA public key (33 bytes compressed)
    
    // ========================
    // POST-QUANTUM SIGNATURE KEYS (Falcon512)
    // ========================
    falcon_sk: Vec<u8>,  // SECRET: Sign transactions
    falcon_pk: Vec<u8>,  // PUBLIC: Others verify signatures
    
    // ========================
    // POST-QUANTUM ENCRYPTION KEYS (Kyber512)
    // ========================
    kyber_sk: Vec<u8>,   // SECRET: Decrypt messages
    kyber_pk: Vec<u8>,   // PUBLIC: Others encrypt for you
}

// 🔑 Response for GET /keys/:user - Returns only PUBLIC keys
#[derive(Serialize)]
struct PublicKeysResponse {
    user: String,
    ecdsa_public_key: String,   // base64-encoded ECDSA public key
    falcon_public_key: String,  // base64-encoded Falcon512 public key
    kyber_public_key: String,   // base64-encoded Kyber512 public key
}

// 📨 Transaction structure
#[derive(Serialize, Deserialize, Clone)]
struct Transaction {
    from: String,
    to: String,
    amount: String,
    timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<u64>,  // For replay protection
}

// ✍️ HYBRID SIGNATURE STRUCTURE
#[derive(Serialize, Deserialize, Clone)]
struct HybridSignature {
    ecdsa_signature: String,    // base64-encoded ECDSA signature (~65 bytes)
    falcon_signature: String,   // base64-encoded Falcon signature (~690 bytes)
    signature_mode: String,     // "hybrid", "legacy", or "pqc-only"
}

// ✍️ Request body for POST /send-eth
#[derive(Deserialize)]
struct SendEthRequest {
    from: String,
    to: String,
    amount: String,
    #[serde(default)]
    signature_mode: Option<String>,  // "hybrid" (default), "legacy", "pqc-only"
}

// 📤 Response for POST /send-eth
#[derive(Serialize)]
struct SendEthResponse {
    step1_transaction: Transaction,
    step2_hybrid_signature: HybridSignature,
    step3_ciphertext: String,
    step4_shared_secret_alice: String,
    step5_shared_secret_bob: String,
    step6_ecdsa_valid: bool,
    step7_falcon_valid: bool,
    step8_hybrid_valid: bool,
    status: String,
    compatibility_info: CompatibilityInfo,
}

// 📊 Compatibility and algorithm information
#[derive(Serialize)]
struct CompatibilityInfo {
    signature_mode: String,
    ecdsa_signature_size: usize,
    falcon_signature_size: usize,
    total_signature_size: usize,
    backward_compatible: bool,   // Can legacy nodes validate?
    forward_compatible: bool,    // Can PQC nodes validate?
    note: String,
}

// -----------------------------------------------------------------------------
// APPLICATION STATE
// -----------------------------------------------------------------------------

struct AppState {
    alice: UserKeys,
    bob: UserKeys,
}

// -----------------------------------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------------------------------

fn get_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos();
    format!("{}.{:09}Z", secs, nanos)
}

/// Hash transaction data before signing (SHA256)
fn hash_transaction(tx_json: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tx_json.as_bytes());
    hasher.finalize().into()
}

/// Sign transaction with ECDSA
fn sign_with_ecdsa(tx_hash: &[u8; 32], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    let secp = Secp256k1::new();
    let sk = EcdsaSecretKey::from_slice(secret_key)
        .map_err(|e| format!("Invalid ECDSA secret key: {}", e))?;
    
    let message = Message::from_digest_slice(tx_hash)
        .map_err(|e| format!("Invalid message hash: {}", e))?;
    
    let signature = secp.sign_ecdsa(&message, &sk);
    Ok(signature.serialize_compact().to_vec())
}

/// Verify ECDSA signature
fn verify_ecdsa(tx_hash: &[u8; 32], signature: &[u8], public_key: &[u8]) -> bool {
    let secp = Secp256k1::new();
    
    let pk = match EcdsaPublicKey::from_slice(public_key) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    
    let message = match Message::from_digest_slice(tx_hash) {
        Ok(msg) => msg,
        Err(_) => return false,
    };
    
    let sig = match secp256k1::ecdsa::Signature::from_compact(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    secp.verify_ecdsa(&message, &sig, &pk).is_ok()
}

// -----------------------------------------------------------------------------
// API ENDPOINTS
// -----------------------------------------------------------------------------

/// GET /keys/{user}
async fn get_user_keys(
    data: web::Data<AppState>,
    path: web::Path<String>
) -> impl Responder {
    let username = path.into_inner().to_lowercase();

    let user = match username.as_str() {
        "alice" => &data.alice,
        "bob" => &data.bob,
        _ => return HttpResponse::NotFound().body("User not found (use 'alice' or 'bob')"),
    };

    let response = PublicKeysResponse {
        user: user.name.clone(),
        ecdsa_public_key: general_purpose::STANDARD.encode(&user.ecdsa_pk),
        falcon_public_key: general_purpose::STANDARD.encode(&user.falcon_pk),
        kyber_public_key: general_purpose::STANDARD.encode(&user.kyber_pk),
    };

    HttpResponse::Ok().json(response)
}

/// POST /send-eth - HYBRID SIGNATURE IMPLEMENTATION
async fn send_eth(
    data: web::Data<AppState>,
    body: web::Json<SendEthRequest>
) -> impl Responder {
    // Determine signature mode
    let sig_mode = body.signature_mode.as_deref().unwrap_or("hybrid");
    
    let (sender, receiver) = match (body.from.to_lowercase().as_str(), body.to.to_lowercase().as_str()) {
        ("alice", "bob") => (&data.alice, &data.bob),
        ("bob", "alice") => (&data.bob, &data.alice),
        _ => return HttpResponse::BadRequest().body("Invalid users (use 'alice' or 'bob')"),
    };

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  💸 {} is sending {} to {}!", sender.name, body.amount, receiver.name);
    println!("║  🔐 Signature Mode: {:<38} ║", sig_mode.to_uppercase());
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // ---------------------------
    // STEP 1: Build transaction
    // ---------------------------
    let transaction = Transaction {
        from: sender.name.clone(),
        to: receiver.name.clone(),
        amount: body.amount.clone(),
        timestamp: get_timestamp(),
        nonce: Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
    };

    let tx_json = serde_json::to_string(&transaction).expect("Failed to serialize");
    println!("✅ Step 1: Transaction created");
    println!("   📝 {}", tx_json);

    // Hash the transaction for ECDSA
    let tx_hash = hash_transaction(&tx_json);

    // ---------------------------
    // STEP 2A: Sign with ECDSA (Classical)
    // ---------------------------
    let ecdsa_sig = if sig_mode != "pqc-only" {
        match sign_with_ecdsa(&tx_hash, &sender.ecdsa_sk) {
            Ok(sig) => sig,
            Err(e) => return HttpResponse::InternalServerError().body(format!("ECDSA signing failed: {}", e)),
        }
    } else {
        Vec::new()  // Empty for PQC-only mode
    };

    let ecdsa_sig_b64 = general_purpose::STANDARD.encode(&ecdsa_sig);
    println!("\n✅ Step 2A: {} signed with ECDSA (classical)", sender.name);
    println!("   ✍️  ECDSA signature size: {} bytes", ecdsa_sig.len());
    if !ecdsa_sig.is_empty() {
        println!("   ✍️  Signature: {}...", &ecdsa_sig_b64[..std::cmp::min(50, ecdsa_sig_b64.len())]);
    }

    // ---------------------------
    // STEP 2B: Sign with Falcon512 (Post-Quantum)
    // ---------------------------
    let falcon_sig = if sig_mode != "legacy" {
        let sender_sk = falcon512::SecretKey::from_bytes(&sender.falcon_sk)
            .expect("Invalid Falcon secret key");
        falcon512::detached_sign(tx_json.as_bytes(), &sender_sk)
    } else {
        // For legacy mode, create empty signature (will be skipped in validation)
        falcon512::DetachedSignature::from_bytes(&vec![0u8; 690]).unwrap_or_else(|_| {
            let sender_sk = falcon512::SecretKey::from_bytes(&sender.falcon_sk).unwrap();
            falcon512::detached_sign(&[0u8; 1], &sender_sk)
        })
    };

    let falcon_sig_b64 = general_purpose::STANDARD.encode(falcon_sig.as_bytes());
    let falcon_sig_size = falcon_sig.as_bytes().len();

    println!("\n✅ Step 2B: {} signed with Falcon512 (post-quantum)", sender.name);
    println!("   🦅 Falcon signature size: {} bytes", falcon_sig_size);
    if sig_mode != "legacy" {
        println!("   🦅 Signature: {}...", &falcon_sig_b64[..50]);
    }

    // Create hybrid signature
    let hybrid_signature = HybridSignature {
        ecdsa_signature: ecdsa_sig_b64.clone(),
        falcon_signature: falcon_sig_b64.clone(),
        signature_mode: sig_mode.to_string(),
    };

    // ---------------------------
    // STEP 3: KEM (Kyber) - Encryption
    // ---------------------------
    let receiver_kyber_pk = kyber512::PublicKey::from_bytes(&receiver.kyber_pk)
        .expect("Invalid receiver Kyber public key");

    let (shared_secret_alice, ciphertext) = kyber512::encapsulate(&receiver_kyber_pk);

    let ciphertext_b64 = general_purpose::STANDARD.encode(ciphertext.as_bytes());
    let ss_alice_b64 = general_purpose::STANDARD.encode(shared_secret_alice.as_bytes());

    println!("\n✅ Step 3: {} encrypted data with {}'s Kyber public key", 
             sender.name, receiver.name);
    println!("   🔐 Ciphertext: {}...", &ciphertext_b64[..50]);

    // ---------------------------
    // STEP 4: KEM Decapsulation
    // ---------------------------
    let receiver_kyber_sk = kyber512::SecretKey::from_bytes(&receiver.kyber_sk)
        .expect("Invalid receiver Kyber secret key");

    let shared_secret_bob = kyber512::decapsulate(&ciphertext, &receiver_kyber_sk);
    let ss_bob_b64 = general_purpose::STANDARD.encode(shared_secret_bob.as_bytes());

    println!("\n✅ Step 4: {} decrypted with their Kyber secret key", receiver.name);

    // ---------------------------
    // STEP 5: VERIFY ECDSA SIGNATURE
    // ---------------------------
    let ecdsa_valid = if sig_mode != "pqc-only" {
        verify_ecdsa(&tx_hash, &ecdsa_sig, &sender.ecdsa_pk)
    } else {
        true  // Skip for PQC-only mode
    };

    println!("\n✅ Step 5: Verify ECDSA signature (legacy compatibility)");
    println!("   {} ECDSA valid: {}", 
             if ecdsa_valid { "✅" } else { "❌" }, 
             ecdsa_valid);

    // ---------------------------
    // STEP 6: VERIFY FALCON SIGNATURE
    // ---------------------------
    let falcon_valid = if sig_mode != "legacy" {
        let sender_pk = falcon512::PublicKey::from_bytes(&sender.falcon_pk)
            .expect("Invalid Falcon public key");

        let sig_bytes = general_purpose::STANDARD.decode(&falcon_sig_b64).unwrap();
        let sig = falcon512::DetachedSignature::from_bytes(&sig_bytes)
            .expect("Invalid Falcon signature");

        falcon512::verify_detached_signature(
            &sig,
            tx_json.as_bytes(),
            &sender_pk
        ).is_ok()
    } else {
        true  // Skip for legacy mode
    };

    println!("\n✅ Step 6: Verify Falcon signature (post-quantum)");
    println!("   {} Falcon valid: {}", 
             if falcon_valid { "🦅" } else { "❌" }, 
             falcon_valid);

    // ---------------------------
    // STEP 7: HYBRID VALIDATION
    // ---------------------------
    let hybrid_valid = match sig_mode {
        "hybrid" => ecdsa_valid && falcon_valid,
        "legacy" => ecdsa_valid,
        "pqc-only" => falcon_valid,
        _ => false,
    };

    println!("\n✅ Step 7: Hybrid validation result");
    println!("   {} Overall valid: {}", 
             if hybrid_valid { "✅" } else { "❌" }, 
             hybrid_valid);

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  🎉 Transaction Complete!                                 ║");
    println!("║  Mode: {:<49} ║", sig_mode);
    println!("║  ECDSA: {:<48} ║", if ecdsa_valid { "✅ Valid" } else { "❌ Invalid/Skipped" });
    println!("║  Falcon: {:<47} ║", if falcon_valid { "✅ Valid" } else { "❌ Invalid/Skipped" });
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Build compatibility info
    let (backward_compat, forward_compat, note) = match sig_mode {
        "hybrid" => (
            true,
            true,
            "Hybrid mode: Legacy nodes validate ECDSA only, PQC nodes validate both".to_string()
        ),
        "legacy" => (
            true,
            false,
            "Legacy mode: Only ECDSA signature, no quantum resistance".to_string()
        ),
        "pqc-only" => (
            false,
            true,
            "PQC-only mode: Only Falcon signature, not compatible with legacy nodes".to_string()
        ),
        _ => (false, false, "Unknown mode".to_string()),
    };

    let response = SendEthResponse {
        step1_transaction: transaction,
        step2_hybrid_signature: hybrid_signature,
        step3_ciphertext: ciphertext_b64,
        step4_shared_secret_alice: ss_alice_b64,
        step5_shared_secret_bob: ss_bob_b64,
        step6_ecdsa_valid: ecdsa_valid,
        step7_falcon_valid: falcon_valid,
        step8_hybrid_valid: hybrid_valid,
        status: format!("✅ {} successfully sent {} to {} (mode: {})", 
                       sender.name, body.amount, receiver.name, sig_mode),
        compatibility_info: CompatibilityInfo {
            signature_mode: sig_mode.to_string(),
            ecdsa_signature_size: ecdsa_sig.len(),
            falcon_signature_size: falcon_sig_size,
            total_signature_size: ecdsa_sig.len() + falcon_sig_size,
            backward_compatible: backward_compat,
            forward_compatible: forward_compat,
            note,
        },
    };

    HttpResponse::Ok().json(response)
}

// -----------------------------------------------------------------------------
// MAIN: Server startup and key generation
// -----------------------------------------------------------------------------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  

    let secp = Secp256k1::new();

    // ---------------------------
    // Generate Alice's keypairs
    // ---------------------------
    println!("🔑 Generating Alice's keypairs...");
    
    // ECDSA keys
    let alice_ecdsa_sk = EcdsaSecretKey::new(&mut secp256k1::rand::thread_rng());
    let alice_ecdsa_pk = EcdsaPublicKey::from_secret_key(&secp, &alice_ecdsa_sk);
    
    // Falcon keys
    let (alice_falcon_pk, alice_falcon_sk) = falcon512::keypair();
    
    // Kyber keys
    let (alice_kyber_pk, alice_kyber_sk) = kyber512::keypair();

    let alice = UserKeys {
        name: "Alice".to_string(),
        ecdsa_sk: alice_ecdsa_sk.secret_bytes().to_vec(),
        ecdsa_pk: alice_ecdsa_pk.serialize().to_vec(),
        falcon_sk: alice_falcon_sk.as_bytes().to_vec(),
        falcon_pk: alice_falcon_pk.as_bytes().to_vec(),
        kyber_sk: alice_kyber_sk.as_bytes().to_vec(),
        kyber_pk: alice_kyber_pk.as_bytes().to_vec(),
    };

    println!("   ✅ Alice's ECDSA keys: {} bytes (SK) / {} bytes (PK)", 
             alice.ecdsa_sk.len(), alice.ecdsa_pk.len());
    println!("   ✅ Alice's Falcon keys: {} bytes (SK) / {} bytes (PK)", 
             alice.falcon_sk.len(), alice.falcon_pk.len());
    println!("   ✅ Alice's Kyber keys: {} bytes (SK) / {} bytes (PK)", 
             alice.kyber_sk.len(), alice.kyber_pk.len());

    // ---------------------------
    // Generate Bob's keypairs
    // ---------------------------
    println!("\n🔑 Generating Bob's keypairs...");
    
    let bob_ecdsa_sk = EcdsaSecretKey::new(&mut secp256k1::rand::thread_rng());
    let bob_ecdsa_pk = EcdsaPublicKey::from_secret_key(&secp, &bob_ecdsa_sk);
    
    let (bob_falcon_pk, bob_falcon_sk) = falcon512::keypair();
    let (bob_kyber_pk, bob_kyber_sk) = kyber512::keypair();

    let bob = UserKeys {
        name: "Bob".to_string(),
        ecdsa_sk: bob_ecdsa_sk.secret_bytes().to_vec(),
        ecdsa_pk: bob_ecdsa_pk.serialize().to_vec(),
        falcon_sk: bob_falcon_sk.as_bytes().to_vec(),
        falcon_pk: bob_falcon_pk.as_bytes().to_vec(),
        kyber_sk: bob_kyber_sk.as_bytes().to_vec(),
        kyber_pk: bob_kyber_pk.as_bytes().to_vec(),
    };

    println!("   ✅ Bob's ECDSA keys: {} bytes (SK) / {} bytes (PK)", 
             bob.ecdsa_sk.len(), bob.ecdsa_pk.len());
    println!("   ✅ Bob's Falcon keys: {} bytes (SK) / {} bytes (PK)", 
             bob.falcon_sk.len(), bob.falcon_pk.len());
    println!("   ✅ Bob's Kyber keys: {} bytes (SK) / {} bytes (PK)", 
             bob.kyber_sk.len(), bob.kyber_pk.len());

    println!("\n📊 Total Keys Generated: 12 (6 for Alice + 6 for Bob)");
    println!("   - 2 ECDSA keys (2 users × 1 keypair each)");
    println!("   - 4 Falcon keys (2 users × 2 keys each)");
    println!("   - 4 Kyber keys (2 users × 2 keys each)");

    println!("\n🔐 Hybrid Signature Comparison:");
    println!("   ┌─────────────────┬──────────┬─────────────────┐");
    println!("   │ Mode            │ Size     │  Compatibility  │");
    println!("   ├─────────────────┼──────────┼─────────────────┤");
    println!("   │ Legacy (ECDSA)  │   ~65 B  │  Legacy only    │");
    println!("   │ PQC (Falcon)    │  ~690 B  │  PQC only       │");
    println!("   │ Hybrid (Both)   │  ~755 B  │  Both!          │");
    println!("   └─────────────────┴──────────┴─────────────────┘");

    let state = web::Data::new(AppState { alice, bob });

    println!("\n🚀 Server running on http://127.0.0.1:8999");
    println!("📖 API Endpoints:");
    println!("   GET  /keys/{{user}}  - Get public keys");
    println!("   POST /send-eth      - Send transaction");
    println!("\n💡 Signature Modes:");
    println!("   - hybrid (default): Both ECDSA + Falcon");
    println!("   - legacy: ECDSA only");
    println!("   - pqc-only: Falcon only\n");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/keys/{user}", web::get().to(get_user_keys))
            .route("/send-eth", web::post().to(send_eth))
    })
    .bind(("127.0.0.1", 8999))?
    .run()
    .await
}