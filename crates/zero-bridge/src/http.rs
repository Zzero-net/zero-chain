//! HTTP coordination API for Trinity Validator signature exchange.
//!
//! Each Trinity Validator runs this API so peers can submit their signatures.
//! Routes:
//!   POST /signatures/ecdsa   — submit an ECDSA release signature
//!   POST /signatures/ed25519 — submit an Ed25519 mint signature
//!   GET  /health              — health check
//!   GET  /status              — pending operation count

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::coordinator::{SignatureCollector, SignatureResult, OpType};

/// Shared state for the HTTP API.
pub struct AppState {
    pub collector: Mutex<SignatureCollector>,
    /// Callback invoked when an operation reaches threshold.
    /// Contains (op_id, op_type, sorted_ecdsa_sigs).
    pub threshold_tx: tokio::sync::mpsc::Sender<ThresholdEvent>,
}

use crate::eip712::ReleaseParams;

/// Event emitted when signature threshold is reached.
#[derive(Debug, Clone)]
pub struct ThresholdEvent {
    pub op_id: [u8; 32],
    pub op_type: OpType,
    pub ecdsa_sigs_sorted: Vec<u8>,
    /// Release parameters (set for Release ops, None for Mint).
    pub release_params: Option<ReleaseParams>,
}

/// Request to submit an ECDSA signature.
#[derive(Serialize, Deserialize)]
pub struct EcdsaSigRequest {
    /// Hex-encoded operation ID (32 bytes)
    pub op_id: String,
    /// Hex-encoded 65-byte ECDSA signature (r || s || v)
    pub signature: String,
}

/// Request to submit an Ed25519 signature.
#[derive(Serialize, Deserialize)]
pub struct Ed25519SigRequest {
    /// Hex-encoded operation ID (32 bytes)
    pub op_id: String,
    /// Hex-encoded 32-byte Ed25519 public key
    pub pubkey: String,
    /// Hex-encoded 64-byte Ed25519 signature
    pub signature: String,
}

/// Response from signature submission.
#[derive(Serialize)]
pub struct SigResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub have: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub need: Option<usize>,
}

/// Status response.
#[derive(Serialize)]
pub struct StatusResponse {
    pub pending_operations: usize,
    pub healthy: bool,
}

/// Build the axum router with all coordination endpoints.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/signatures/ecdsa", post(submit_ecdsa))
        .route("/signatures/ed25519", post(submit_ed25519))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let collector = state.collector.lock().await;
    Json(StatusResponse {
        pending_operations: collector.pending_count(),
        healthy: true,
    })
}

async fn submit_ecdsa(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EcdsaSigRequest>,
) -> Result<Json<SigResponse>, (StatusCode, String)> {
    let op_id = decode_bytes32(&req.op_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad op_id: {e}")))?;
    let sig = decode_bytes65(&req.signature)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad signature: {e}")))?;

    let mut collector = state.collector.lock().await;
    match collector.add_ecdsa_signature(&op_id, &sig) {
        Ok(SignatureResult::Pending { have, need }) => {
            info!(op = hex::encode(op_id), have, need, "ECDSA signature accepted, pending");
            Ok(Json(SigResponse {
                status: "pending".into(),
                have: Some(have),
                need: Some(need),
            }))
        }
        Ok(SignatureResult::ThresholdMet { op_id, ecdsa_sigs_sorted }) => {
            info!(op = hex::encode(op_id), "ECDSA threshold met!");
            // Notify the service loop
            let _ = state.threshold_tx.send(ThresholdEvent {
                op_id,
                op_type: OpType::Release,
                ecdsa_sigs_sorted,
                release_params: None, // Filled by service when it initiates the release
            }).await;
            Ok(Json(SigResponse {
                status: "threshold_met".into(),
                have: None,
                need: None,
            }))
        }
        Err(e) => {
            warn!(op = hex::encode(op_id), err = %e, "ECDSA signature rejected");
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

async fn submit_ed25519(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Ed25519SigRequest>,
) -> Result<Json<SigResponse>, (StatusCode, String)> {
    let op_id = decode_bytes32(&req.op_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad op_id: {e}")))?;
    let pubkey = decode_bytes32(&req.pubkey)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad pubkey: {e}")))?;
    let sig = decode_bytes64(&req.signature)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad signature: {e}")))?;

    let mut collector = state.collector.lock().await;
    match collector.add_ed25519_signature(&op_id, &pubkey, &sig) {
        Ok(SignatureResult::Pending { have, need }) => {
            info!(op = hex::encode(op_id), have, need, "Ed25519 signature accepted, pending");
            Ok(Json(SigResponse {
                status: "pending".into(),
                have: Some(have),
                need: Some(need),
            }))
        }
        Ok(SignatureResult::ThresholdMet { op_id, .. }) => {
            info!(op = hex::encode(op_id), "Ed25519 threshold met!");
            let _ = state.threshold_tx.send(ThresholdEvent {
                op_id,
                op_type: OpType::Mint,
                ecdsa_sigs_sorted: Vec::new(),
                release_params: None,
            }).await;
            Ok(Json(SigResponse {
                status: "threshold_met".into(),
                have: None,
                need: None,
            }))
        }
        Err(e) => {
            warn!(op = hex::encode(op_id), err = %e, "Ed25519 signature rejected");
            Err((StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

// --- Hex helpers ---

fn decode_bytes32(hex_str: &str) -> Result<[u8; 32], String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_bytes64(hex_str: &str) -> Result<[u8; 64], String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| e.to_string())?;
    if bytes.len() != 64 {
        return Err(format!("expected 64 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_bytes65(hex_str: &str) -> Result<[u8; 65], String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| e.to_string())?;
    if bytes.len() != 65 {
        return Err(format!("expected 65 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 65];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Send our ECDSA signature to a peer validator.
pub async fn send_ecdsa_to_peer(
    client: &reqwest::Client,
    peer_endpoint: &str,
    op_id: &[u8; 32],
    signature: &[u8; 65],
) -> Result<(), String> {
    let url = format!("{}/signatures/ecdsa", peer_endpoint);
    let req = EcdsaSigRequest {
        op_id: hex::encode(op_id),
        signature: hex::encode(signature),
    };

    let resp = client.post(&url)
        .json(&req)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("failed to reach peer {}: {}", peer_endpoint, e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!("peer {} rejected signature: {}", peer_endpoint, body))
    }
}

/// Send our Ed25519 signature to a peer validator.
pub async fn send_ed25519_to_peer(
    client: &reqwest::Client,
    peer_endpoint: &str,
    op_id: &[u8; 32],
    pubkey: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), String> {
    let url = format!("{}/signatures/ed25519", peer_endpoint);
    let req = Ed25519SigRequest {
        op_id: hex::encode(op_id),
        pubkey: hex::encode(pubkey),
        signature: hex::encode(signature),
    };

    let resp = client.post(&url)
        .json(&req)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("failed to reach peer {}: {}", peer_endpoint, e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!("peer {} rejected signature: {}", peer_endpoint, body))
    }
}
