use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use ed25519_dalek::{Signature as DalekSig, VerifyingKey};
use parking_lot::RwLock;
use serde::Deserialize;
use tracing::{error, info, warn};

use zero_consensus::Node;
use zero_storage::BridgeOp;
use zero_types::PubKey;

/// Attestation from a Trinity Validator (Ed25519 signature over mint message).
#[derive(Deserialize)]
struct Attestation {
    /// Hex-encoded 32-byte Ed25519 public key of the signing validator.
    pubkey: String,
    /// Hex-encoded 64-byte Ed25519 signature.
    signature: String,
}

/// POST /bridge/mint request body.
#[derive(Deserialize)]
struct MintRequest {
    /// Hex-encoded 32-byte recipient public key on Zero chain.
    recipient: String,
    /// Amount in units to mint (1 unit = 0.01 Z).
    amount: u64,
    /// Source chain name (e.g., "base", "arbitrum").
    source_chain: String,
    /// Hex-encoded 32-byte source transaction hash (deposit tx on L2).
    source_tx: String,
    /// Ed25519 attestations from Trinity Validators.
    attestations: Vec<Attestation>,
}

#[derive(Clone)]
pub struct BridgeApiState {
    node: Arc<RwLock<Node>>,
    /// Ed25519 public keys of the 3 Trinity Validators.
    trinity_pubkeys: Vec<PubKey>,
    /// Required signature threshold (2 of 3).
    threshold: usize,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn handle_mint(
    State(state): State<BridgeApiState>,
    Json(req): Json<MintRequest>,
) -> impl IntoResponse {
    // Parse recipient
    let recipient_hex = req.recipient.trim().to_lowercase();
    let recipient_hex = recipient_hex.strip_prefix("0x").unwrap_or(&recipient_hex);
    let recipient: [u8; 32] = match hex::decode(recipient_hex) {
        Ok(bytes) => match bytes.try_into() {
            Ok(pk) => pk,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "recipient must be 32 bytes"})),
                );
            }
        },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid recipient hex"})),
            );
        }
    };

    // Parse source_tx
    let source_tx_hex = req.source_tx.trim().to_lowercase();
    let source_tx_hex = source_tx_hex.strip_prefix("0x").unwrap_or(&source_tx_hex);
    let _source_tx: [u8; 32] = match hex::decode(source_tx_hex) {
        Ok(bytes) => match bytes.try_into() {
            Ok(h) => h,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "source_tx must be 32 bytes"})),
                );
            }
        },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid source_tx hex"})),
            );
        }
    };

    if req.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "amount must be > 0"})),
        );
    }

    if req.attestations.len() < state.threshold {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("need at least {} attestations, got {}", state.threshold, req.attestations.len())
            })),
        );
    }

    // Build the canonical signing message using BridgeOp::signing_bytes()
    // This must match the format used by the bridge service when signing.
    let mint_op = BridgeOp::Mint {
        recipient,
        amount: req.amount,
        source_chain: req.source_chain.clone(),
        source_tx: source_tx_hex.to_string(),
    };
    let message = mint_op.signing_bytes();

    // Verify attestations
    let mut valid_signers: Vec<PubKey> = Vec::new();

    for att in &req.attestations {
        let pk_hex = att.pubkey.trim().to_lowercase();
        let pk_hex = pk_hex.strip_prefix("0x").unwrap_or(&pk_hex);
        let pk_bytes: [u8; 32] = match hex::decode(pk_hex).ok().and_then(|b| b.try_into().ok()) {
            Some(pk) => pk,
            None => {
                warn!(pubkey = pk_hex, "Invalid attestation pubkey format");
                continue;
            }
        };

        // Check this pubkey is a known Trinity Validator
        if !state.trinity_pubkeys.contains(&pk_bytes) {
            warn!(pubkey = pk_hex, "Unknown Trinity Validator pubkey");
            continue;
        }

        // Check for duplicate signer
        if valid_signers.contains(&pk_bytes) {
            warn!(pubkey = pk_hex, "Duplicate attestation from same validator");
            continue;
        }

        // Parse and verify signature
        let sig_hex = att.signature.trim().to_lowercase();
        let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(&sig_hex);
        let sig_bytes: [u8; 64] = match hex::decode(sig_hex).ok().and_then(|b| b.try_into().ok()) {
            Some(s) => s,
            None => {
                warn!(pubkey = pk_hex, "Invalid attestation signature format");
                continue;
            }
        };

        let vk = match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(vk) => vk,
            Err(_) => {
                warn!(pubkey = pk_hex, "Invalid Ed25519 public key");
                continue;
            }
        };

        let sig = DalekSig::from_bytes(&sig_bytes);
        if vk.verify_strict(&message, &sig).is_ok() {
            valid_signers.push(pk_bytes);
        } else {
            warn!(pubkey = pk_hex, "Attestation signature verification failed");
        }
    }

    if valid_signers.len() < state.threshold {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": format!(
                    "insufficient valid attestations: {} of {} required",
                    valid_signers.len(),
                    state.threshold
                )
            })),
        );
    }

    // Execute the mint
    let result = {
        let node = state.node.read();
        let mut exec = node.executor().write();
        exec.bridge_mint(&recipient, req.amount, now_ms())
    };

    match result {
        Ok(()) => {
            info!(
                recipient = recipient_hex,
                amount = req.amount,
                source_tx = source_tx_hex,
                signers = valid_signers.len(),
                "Bridge mint executed"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "minted",
                    "recipient": recipient_hex,
                    "amount": req.amount,
                    "amount_z": format!("{:.2}", req.amount as f64 / 100.0),
                    "source_tx": source_tx_hex,
                    "signers": valid_signers.len(),
                })),
            )
        }
        Err(e) => {
            error!(err = %e, "Bridge mint failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        }
    }
}

/// Start the bridge mint API server. Returns a JoinHandle.
pub fn start_bridge_api(
    node: Arc<RwLock<Node>>,
    trinity_pubkeys: Vec<PubKey>,
    listen: String,
) -> tokio::task::JoinHandle<()> {
    let state = BridgeApiState {
        node,
        trinity_pubkeys,
        threshold: 2,
    };

    info!(
        listen = %listen,
        validators = state.trinity_pubkeys.len(),
        threshold = state.threshold,
        "Starting bridge mint API"
    );

    tokio::spawn(async move {
        let app = Router::new()
            .route("/bridge/mint", post(handle_mint))
            .with_state(state);

        let listener = match tokio::net::TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                error!(err = %e, addr = %listen, "Failed to bind bridge API listener");
                return;
            }
        };

        if let Err(e) = axum::serve(listener, app).await {
            error!(err = %e, "Bridge API server error");
        }
    })
}
