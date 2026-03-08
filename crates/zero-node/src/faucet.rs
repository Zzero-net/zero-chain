use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use tracing::{error, info, warn};

use zero_consensus::Node;
use zero_crypto::KeyPair;
use zero_types::Transfer;

#[derive(Clone)]
pub struct FaucetState {
    node: Arc<RwLock<Node>>,
    keypair: Arc<KeyPair>,
    drip_amount: u32,
    cooldown_secs: u64,
    last_drip: Arc<Mutex<HashMap<[u8; 32], u64>>>,
}

#[derive(Deserialize)]
struct FaucetRequest {
    recipient: String,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn handle_drip(
    State(state): State<FaucetState>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    let recipient_hex = req.recipient.trim().to_lowercase();
    let recipient_hex = recipient_hex.strip_prefix("0x").unwrap_or(&recipient_hex);

    let recipient: [u8; 32] = match hex::decode(recipient_hex) {
        Ok(bytes) => match bytes.try_into() {
            Ok(pk) => pk,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "recipient must be 32 bytes (64 hex chars)"})),
                );
            }
        },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid hex encoding"})),
            );
        }
    };

    // Check cooldown
    {
        let last = state.last_drip.lock();
        if let Some(&ts) = last.get(&recipient) {
            let elapsed = now_secs().saturating_sub(ts);
            if elapsed < state.cooldown_secs {
                let remaining = state.cooldown_secs - elapsed;
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "error": format!("cooldown active — try again in {}s", remaining)
                    })),
                );
            }
        }
    }

    // Get faucet's current nonce
    let nonce = {
        let node = state.node.read();
        let exec = node.executor().read();
        exec.accounts().get_or_default(&state.keypair.public_key()).nonce + 1
    };

    // Build and sign transfer
    let mut tx = Transfer {
        from: state.keypair.public_key(),
        to: recipient,
        amount: state.drip_amount,
        nonce,
        signature: [0u8; 64],
    };
    tx.signature = state.keypair.sign_transfer(&tx);

    let tx_hash = zero_crypto::blake3_hash(&tx.to_storage_bytes());

    // Submit to consensus pipeline
    match state.node.write().submit_transfer(tx, now_ms()) {
        Ok(()) => {
            state.last_drip.lock().insert(recipient, now_secs());

            info!(
                recipient = recipient_hex,
                amount = state.drip_amount,
                nonce,
                "Faucet drip sent"
            );

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "tx_hash": hex::encode(tx_hash),
                    "amount": state.drip_amount,
                    "amount_z": format!("{:.2}", state.drip_amount as f64 / 100.0),
                })),
            )
        }
        Err(e) => {
            warn!(err = %e, "Faucet transfer rejected");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        }
    }
}

async fn handle_status(State(state): State<FaucetState>) -> impl IntoResponse {
    let faucet_pk = state.keypair.public_key();
    let balance = {
        let node = state.node.read();
        let exec = node.executor().read();
        exec.accounts().balance(&faucet_pk)
    };

    Json(serde_json::json!({
        "faucet_pubkey": hex::encode(faucet_pk),
        "balance": balance,
        "balance_z": format!("{:.2}", balance as f64 / 100.0),
        "drip_amount": state.drip_amount,
        "drip_z": format!("{:.2}", state.drip_amount as f64 / 100.0),
        "cooldown_secs": state.cooldown_secs,
    }))
}

/// Start the faucet HTTP server. Returns a JoinHandle.
pub fn start_faucet(
    node: Arc<RwLock<Node>>,
    keypair: KeyPair,
    listen: String,
    drip_amount: u32,
    cooldown_secs: u64,
) -> tokio::task::JoinHandle<()> {
    let state = FaucetState {
        node,
        keypair: Arc::new(keypair),
        drip_amount,
        cooldown_secs,
        last_drip: Arc::new(Mutex::new(HashMap::new())),
    };

    info!(
        listen = %listen,
        faucet_pubkey = hex::encode(state.keypair.public_key()),
        drip_amount,
        cooldown_secs,
        "Starting faucet API"
    );

    tokio::spawn(async move {
        let app = Router::new()
            .route("/faucet", post(handle_drip))
            .route("/faucet/status", get(handle_status))
            .with_state(state);

        let listener = match tokio::net::TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                error!(err = %e, addr = %listen, "Failed to bind faucet listener");
                return;
            }
        };

        if let Err(e) = axum::serve(listener, app).await {
            error!(err = %e, "Faucet server error");
        }
    })
}
