//! HTTP coordination API for Trinity Validator signature exchange.
//!
//! Each Trinity Validator runs this API so peers can submit their signatures.
//! Routes:
//!   POST /signatures/ecdsa   — submit an ECDSA release signature
//!   POST /signatures/ed25519 — submit an Ed25519 mint signature
//!   GET  /health              — detailed health check (JSON)
//!   GET  /status              — pending operation count

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::coordinator::{OpType, SignatureCollector, SignatureResult};

/// Runtime statistics tracked by the bridge service.
pub struct BridgeStats {
    /// Unix timestamp when the service started.
    pub started_at: u64,
    /// Total number of operations that reached threshold and were executed.
    pub ops_completed: AtomicU64,
    /// Total mints completed.
    pub mints_completed: AtomicU64,
    /// Total releases completed.
    pub releases_completed: AtomicU64,
    /// Last poll timestamp per chain (chain_name -> unix_timestamp).
    pub last_poll_time: Mutex<HashMap<String, u64>>,
    /// Last block seen per chain (chain_name -> block_number).
    pub last_block: Mutex<HashMap<String, u64>>,
}

impl BridgeStats {
    /// Create a new stats tracker, recording the current time as start.
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            started_at: now,
            ops_completed: AtomicU64::new(0),
            mints_completed: AtomicU64::new(0),
            releases_completed: AtomicU64::new(0),
            last_poll_time: Mutex::new(HashMap::new()),
            last_block: Mutex::new(HashMap::new()),
        }
    }

    /// Record a completed operation.
    pub fn record_completion(&self, op_type: &OpType) {
        self.ops_completed.fetch_add(1, Ordering::Relaxed);
        match op_type {
            OpType::Mint => { self.mints_completed.fetch_add(1, Ordering::Relaxed); }
            OpType::Release => { self.releases_completed.fetch_add(1, Ordering::Relaxed); }
        }
    }

    /// Record a poll for a given chain.
    pub async fn record_poll(&self, chain: &str, block: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.last_poll_time.lock().await.insert(chain.to_string(), now);
        self.last_block.lock().await.insert(chain.to_string(), block);
    }
}

/// Shared state for the HTTP API.
pub struct AppState {
    pub collector: Mutex<SignatureCollector>,
    /// Callback invoked when an operation reaches threshold.
    /// Contains (op_id, op_type, sorted_ecdsa_sigs).
    pub threshold_tx: tokio::sync::mpsc::Sender<ThresholdEvent>,
    /// Runtime statistics for health monitoring.
    pub stats: BridgeStats,
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
    /// Release parameters (included when sharing bridge-out signatures
    /// so the peer can auto-create the operation and sign it too).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_params: Option<ReleaseParamsJson>,
    /// Hex-encoded EIP-712 digest (32 bytes) — included so the peer can
    /// verify the signature without needing chain-specific domain separators.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// JSON-serializable release parameters for peer sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseParamsJson {
    pub token: String,
    pub amount: u64,
    pub recipient: String,
    pub bridge_id: String,
    pub dest_chain: String,
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

/// Per-chain status in the health response.
#[derive(Serialize)]
pub struct ChainHealth {
    /// Last time this chain was polled (unix timestamp).
    pub last_poll_time: Option<u64>,
    /// Seconds since last poll (None if never polled).
    pub secs_since_poll: Option<u64>,
    /// Last block number seen on this chain.
    pub last_block: Option<u64>,
}

/// Detailed health check response.
#[derive(Serialize)]
pub struct HealthResponse {
    /// Overall status: "healthy" or "degraded".
    pub status: String,
    /// Service uptime in seconds.
    pub uptime_secs: u64,
    /// Number of pending operations awaiting signatures.
    pub pending_operations: usize,
    /// Total operations completed (reached threshold and executed).
    pub ops_completed: u64,
    /// Total mints completed.
    pub mints_completed: u64,
    /// Total releases completed.
    pub releases_completed: u64,
    /// Per-chain health information.
    pub chains: HashMap<String, ChainHealth>,
    /// Current unix timestamp.
    pub timestamp: u64,
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

async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let uptime_secs = now - state.stats.started_at;
    let pending_operations = state.collector.lock().await.pending_count();
    let ops_completed = state.stats.ops_completed.load(Ordering::Relaxed);
    let mints_completed = state.stats.mints_completed.load(Ordering::Relaxed);
    let releases_completed = state.stats.releases_completed.load(Ordering::Relaxed);

    let poll_times = state.stats.last_poll_time.lock().await;
    let last_blocks = state.stats.last_block.lock().await;

    let mut chains = HashMap::new();
    let mut degraded = false;

    // Build per-chain health from all known chains
    for (chain, &poll_time) in poll_times.iter() {
        let secs_since = now.saturating_sub(poll_time);
        // Consider degraded if any chain hasn't been polled in 60 seconds
        if secs_since > 60 {
            degraded = true;
        }
        chains.insert(
            chain.clone(),
            ChainHealth {
                last_poll_time: Some(poll_time),
                secs_since_poll: Some(secs_since),
                last_block: last_blocks.get(chain).copied(),
            },
        );
    }

    // If uptime < 30s, don't mark as degraded (still starting up)
    if uptime_secs < 30 {
        degraded = false;
    }

    let status = if degraded { "degraded" } else { "healthy" }.to_string();

    Json(HealthResponse {
        status,
        uptime_secs,
        pending_operations,
        ops_completed,
        mints_completed,
        releases_completed,
        chains,
        timestamp: now,
    })
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

    // For release operations: if the operation doesn't exist but release_params
    // are provided, auto-create it so peers can participate in signing.
    if collector.get_operation(&op_id).is_none() {
        if let Some(ref params_json) = req.release_params {
            let token = decode_bytes20(&params_json.token).unwrap_or([0u8; 20]);
            let recipient = decode_bytes20(&params_json.recipient).unwrap_or([0u8; 20]);
            let bridge_id = decode_bytes32(&params_json.bridge_id).unwrap_or(op_id);

            let params = ReleaseParams {
                token,
                amount: params_json.amount,
                recipient,
                bridge_id,
                dest_chain: params_json.dest_chain.clone(),
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Parse the EIP-712 digest from the peer so we can verify signatures.
            let digest = req.digest.as_ref().and_then(|d| decode_bytes32(d).ok());

            // Create the operation so the incoming signature can be added.
            // The service's sign_pending_releases() will detect this and add our own sig.
            collector.create_operation(op_id, OpType::Release, digest, now);
            collector.set_release_params(&op_id, params);

            info!(
                op = hex::encode(op_id),
                chain = %params_json.dest_chain,
                "auto-created release operation from peer params"
            );
        }
    }

    match collector.add_ecdsa_signature(&op_id, &sig) {
        Ok(SignatureResult::Pending { have, need }) => {
            info!(
                op = hex::encode(op_id),
                have, need, "ECDSA signature accepted, pending"
            );
            Ok(Json(SigResponse {
                status: "pending".into(),
                have: Some(have),
                need: Some(need),
            }))
        }
        Ok(SignatureResult::ThresholdMet {
            op_id,
            ecdsa_sigs_sorted,
        }) => {
            info!(op = hex::encode(op_id), "ECDSA threshold met!");
            // Extract release params from the pending operation
            let release_params = collector
                .get_operation(&op_id)
                .and_then(|op| op.release_params.clone());
            // Notify the service loop
            let _ = state
                .threshold_tx
                .send(ThresholdEvent {
                    op_id,
                    op_type: OpType::Release,
                    ecdsa_sigs_sorted,
                    release_params,
                })
                .await;
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
            info!(
                op = hex::encode(op_id),
                have, need, "Ed25519 signature accepted, pending"
            );
            Ok(Json(SigResponse {
                status: "pending".into(),
                have: Some(have),
                need: Some(need),
            }))
        }
        Ok(SignatureResult::ThresholdMet { op_id, .. }) => {
            info!(op = hex::encode(op_id), "Ed25519 threshold met!");
            let _ = state
                .threshold_tx
                .send(ThresholdEvent {
                    op_id,
                    op_type: OpType::Mint,
                    ecdsa_sigs_sorted: Vec::new(),
                    release_params: None,
                })
                .await;
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

fn decode_bytes20(hex_str: &str) -> Result<[u8; 20], String> {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).map_err(|e| e.to_string())?;
    if bytes.len() != 20 {
        return Err(format!("expected 20 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 20];
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
    release_params: Option<&ReleaseParams>,
    digest: Option<&[u8; 32]>,
) -> Result<(), String> {
    let url = format!("{}/signatures/ecdsa", peer_endpoint);
    let req = EcdsaSigRequest {
        op_id: hex::encode(op_id),
        signature: hex::encode(signature),
        release_params: release_params.map(|p| ReleaseParamsJson {
            token: hex::encode(p.token),
            amount: p.amount,
            recipient: hex::encode(p.recipient),
            bridge_id: hex::encode(p.bridge_id),
            dest_chain: p.dest_chain.clone(),
        }),
        digest: digest.map(hex::encode),
    };

    let resp = client
        .post(&url)
        .json(&req)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("failed to reach peer {}: {}", peer_endpoint, e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!(
            "peer {} rejected signature: {}",
            peer_endpoint, body
        ))
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

    let resp = client
        .post(&url)
        .json(&req)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("failed to reach peer {}: {}", peer_endpoint, e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!(
            "peer {} rejected signature: {}",
            peer_endpoint, body
        ))
    }
}
