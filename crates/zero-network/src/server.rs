use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use zero_consensus::Node;
use zero_storage::{BridgeOp, RateLimiter, TransferExecutor};
use zero_types::Transfer;
use zero_types::params::BRIDGE_OUT_FEE;

use crate::proto::{zero_service_server::ZeroService, *};

/// Per-IP rate limiter: sliding 1-second window, rejects above threshold.
struct IpRateLimiter {
    windows: HashMap<IpAddr, (u64, u32)>,
    max_per_sec: u32,
}

impl IpRateLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self {
            windows: HashMap::new(),
            max_per_sec,
        }
    }

    fn check(&mut self, ip: IpAddr, now_ms: u64) -> Result<(), u32> {
        let entry = self.windows.entry(ip).or_insert((now_ms, 0));
        if now_ms >= entry.0 + 1000 {
            entry.0 = now_ms;
            entry.1 = 0;
        }
        if entry.1 >= self.max_per_sec {
            return Err(entry.1);
        }
        entry.1 += 1;
        Ok(())
    }

    fn cleanup(&mut self, now_ms: u64) {
        self.windows
            .retain(|_, (start, _)| now_ms < *start + 10_000);
    }
}

/// Tracks bridge operations for status queries.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BridgeOperation {
    pub bridge_id: String,
    pub direction: String,
    pub status: String,
    pub source_chain: String,
    pub token: String,
    pub z_amount: u32,
    pub attestations: u32,
    pub required: u32,
    pub created_at: u64,
    /// For bridge-out: hex-encoded destination address on L2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_address: Option<String>,
    /// For bridge-out: hex-encoded sender Zero public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_pubkey: Option<String>,
}

/// Shared bridge operations store.
pub type BridgeOps = Arc<Mutex<HashMap<String, BridgeOperation>>>;

pub struct ZeroServer {
    node: Arc<RwLock<Node>>,
    executor: Arc<RwLock<TransferExecutor>>,
    start_time: Instant,
    peer_count: u32,
    bridge_ops: BridgeOps,
    /// Per-account rate limiter (100 tx/sec/account).
    account_limiter: Mutex<RateLimiter>,
    /// Per-IP rate limiter (1000 req/sec/IP).
    ip_limiter: Mutex<IpRateLimiter>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

impl ZeroServer {
    pub fn new(
        node: Arc<RwLock<Node>>,
        executor: Arc<RwLock<TransferExecutor>>,
        peer_count: u32,
        bridge_ops: BridgeOps,
    ) -> Self {
        Self {
            node,
            executor,
            start_time: Instant::now(),
            peer_count,
            bridge_ops,
            account_limiter: Mutex::new(RateLimiter::new()),
            ip_limiter: Mutex::new(IpRateLimiter::new(1000)),
        }
    }

    /// Check IP-based rate limit. Returns Ok(()) or Status::resource_exhausted.
    #[allow(clippy::result_large_err)]
    fn check_ip_rate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if let Some(addr) = request.remote_addr() {
            let ip = addr.ip();
            let now = now_ms();
            if let Err(rate) = self.ip_limiter.lock().check(ip, now) {
                warn!(ip = %ip, rate, "IP rate limit exceeded");
                return Err(Status::resource_exhausted(format!(
                    "rate limit exceeded: {} requests/sec from {}",
                    rate, ip
                )));
            }
        }
        Ok(())
    }

    /// Check per-account rate limit. Returns Ok(()) or Status::resource_exhausted.
    #[allow(clippy::result_large_err)]
    fn check_account_rate(&self, account: &[u8; 32]) -> Result<(), Status> {
        let now = now_ms();
        if let Err(rate) = self.account_limiter.lock().check(account, now) {
            warn!(
                account = hex::encode(account),
                rate, "account rate limit exceeded"
            );
            return Err(Status::resource_exhausted(format!(
                "account rate limit exceeded: {} tx/sec",
                rate
            )));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl ZeroService for ZeroServer {
    type StreamTransfersStream = ReceiverStream<Result<TransferRecord, Status>>;

    async fn send(&self, request: Request<SendRequest>) -> Result<Response<SendResponse>, Status> {
        self.check_ip_rate(&request)?;
        let req = request.into_inner();

        let from: [u8; 32] = req
            .from
            .try_into()
            .map_err(|_| Status::invalid_argument("from must be 32 bytes"))?;
        let to: [u8; 32] = req
            .to
            .try_into()
            .map_err(|_| Status::invalid_argument("to must be 32 bytes"))?;
        let signature: [u8; 64] = req
            .signature
            .try_into()
            .map_err(|_| Status::invalid_argument("signature must be 64 bytes"))?;

        self.check_account_rate(&from)?;

        let transfer = Transfer {
            from,
            to,
            amount: req.amount,
            nonce: req.nonce,
            signature,
        };

        // Compute tx hash for the response
        let tx_hash = zero_crypto::blake3_hash(&transfer.to_storage_bytes());

        // Submit to the consensus pipeline (pending pool → event → DAG → finalization → execution)
        self.node
            .write()
            .submit_transfer(transfer, now_ms())
            .map_err(|e: zero_types::ZeroError| Status::failed_precondition(e.to_string()))?;

        Ok(Response::new(SendResponse {
            tx_hash: tx_hash.to_vec(),
            seq: 0, // seq assigned after finalization
        }))
    }

    async fn get_transfer(
        &self,
        request: Request<GetTransferRequest>,
    ) -> Result<Response<GetTransferResponse>, Status> {
        self.check_ip_rate(&request)?;
        let req = request.into_inner();
        let hash: [u8; 32] = req
            .tx_hash
            .try_into()
            .map_err(|_| Status::invalid_argument("tx_hash must be 32 bytes"))?;

        let executor = self.executor.read();
        match executor.transfer_log().find_by_hash(&hash) {
            Some((seq, tx)) => Ok(Response::new(GetTransferResponse {
                from: tx.from.to_vec(),
                to: tx.to.to_vec(),
                amount: tx.amount,
                nonce: tx.nonce,
                signature: tx.signature.to_vec(),
                seq,
                status: "finalized".into(),
            })),
            None => Ok(Response::new(GetTransferResponse {
                status: "not_found".into(),
                ..Default::default()
            })),
        }
    }

    async fn get_history(
        &self,
        request: Request<GetHistoryRequest>,
    ) -> Result<Response<GetHistoryResponse>, Status> {
        self.check_ip_rate(&request)?;
        let req = request.into_inner();
        let account: [u8; 32] = req
            .account
            .try_into()
            .map_err(|_| Status::invalid_argument("account must be 32 bytes"))?;

        let executor = self.executor.read();
        let limit = std::cmp::min(req.limit as usize, 100);
        let recent = executor.transfer_log().recent_with_seq(limit * 10); // overscan then filter

        let transfers: Vec<TransferRecord> = recent
            .iter()
            .filter(|(_, tx)| tx.from == account || tx.to == account)
            .take(limit)
            .map(|(seq, tx)| {
                let hash = zero_crypto::blake3_hash(&tx.to_storage_bytes());
                TransferRecord {
                    from: tx.from.to_vec(),
                    to: tx.to.to_vec(),
                    amount: tx.amount,
                    nonce: tx.nonce,
                    seq: *seq,
                    tx_hash: hash.to_vec(),
                }
            })
            .collect();

        Ok(Response::new(GetHistoryResponse { transfers }))
    }

    async fn get_balance(
        &self,
        request: Request<GetBalanceRequest>,
    ) -> Result<Response<GetBalanceResponse>, Status> {
        self.check_ip_rate(&request)?;
        let req = request.into_inner();
        let account: [u8; 32] = req
            .account
            .try_into()
            .map_err(|_| Status::invalid_argument("account must be 32 bytes"))?;

        let balance = self.executor.read().accounts().balance(&account);
        Ok(Response::new(GetBalanceResponse { balance }))
    }

    async fn get_account(
        &self,
        request: Request<GetAccountRequest>,
    ) -> Result<Response<GetAccountResponse>, Status> {
        self.check_ip_rate(&request)?;
        let req = request.into_inner();
        let account: [u8; 32] = req
            .account
            .try_into()
            .map_err(|_| Status::invalid_argument("account must be 32 bytes"))?;

        let acct = self.executor.read().accounts().get_or_default(&account);
        Ok(Response::new(GetAccountResponse {
            balance: acct.balance,
            nonce: acct.nonce,
            head: acct.head.to_vec(),
            flags: acct.flags,
        }))
    }

    async fn bridge_in(
        &self,
        request: Request<BridgeInRequest>,
    ) -> Result<Response<BridgeInResponse>, Status> {
        self.check_ip_rate(&request)?;
        let req = request.into_inner();

        let recipient: [u8; 32] = req
            .zero_recipient
            .try_into()
            .map_err(|_| Status::invalid_argument("zero_recipient must be 32 bytes"))?;

        // Generate a deterministic bridge_id from the source chain tx
        let bridge_id = {
            let mut data = Vec::new();
            data.extend_from_slice(req.source_chain.as_bytes());
            data.push(b':');
            data.extend_from_slice(req.tx_hash.as_bytes());
            hex::encode(zero_crypto::blake3_hash(&data))
        };

        info!(
            chain = req.source_chain,
            token = req.token,
            tx = req.tx_hash,
            recipient = hex::encode(recipient),
            bridge_id = bridge_id,
            "Bridge-in request recorded"
        );

        // Record the pending operation
        let op = BridgeOperation {
            bridge_id: bridge_id.clone(),
            direction: "in".into(),
            status: "pending_attestation".into(),
            source_chain: req.source_chain,
            token: req.token,
            z_amount: 0, // set when attestations are collected and mint executes
            attestations: 0,
            required: 2,
            created_at: now_ms(),
            dest_address: None,
            sender_pubkey: None,
        };
        self.bridge_ops.lock().insert(bridge_id.clone(), op);

        Ok(Response::new(BridgeInResponse {
            bridge_id,
            status: "pending_attestation".into(),
            z_amount: 0,
        }))
    }

    async fn bridge_out(
        &self,
        request: Request<BridgeOutRequest>,
    ) -> Result<Response<BridgeOutResponse>, Status> {
        self.check_ip_rate(&request)?;
        let req = request.into_inner();

        let sender: [u8; 32] = req
            .from
            .try_into()
            .map_err(|_| Status::invalid_argument("from must be 32 bytes"))?;
        let signature: [u8; 64] = req
            .signature
            .try_into()
            .map_err(|_| Status::invalid_argument("signature must be 64 bytes"))?;

        self.check_account_rate(&sender)?;

        if req.z_amount == 0 {
            return Err(Status::invalid_argument("z_amount must be > 0"));
        }

        // Build the canonical burn message and verify the Ed25519 signature
        let burn_op = BridgeOp::Burn {
            sender,
            amount: req.z_amount as u64,
            dest_chain: req.dest_chain.clone(),
            dest_address: req.dest_address.clone(),
        };
        let signing_bytes = burn_op.signing_bytes();

        // Verify Ed25519 signature
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&sender)
            .map_err(|_| Status::invalid_argument("invalid Ed25519 public key"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&signature);
        vk.verify_strict(&signing_bytes, &sig)
            .map_err(|_| Status::unauthenticated("invalid burn signature"))?;

        // Burn the Z from the sender's account (amount + bridge-out fee)
        let total_burn = req.z_amount + BRIDGE_OUT_FEE;
        {
            let burned = self.executor.read().accounts().burn(&sender, total_burn);
            if !burned {
                return Err(Status::failed_precondition(
                    format!("insufficient balance for burn (need {} + {} fee = {} units)", req.z_amount, BRIDGE_OUT_FEE, total_burn),
                ));
            }
        }
        // Collect the bridge-out fee
        self.executor.write().collect_fee(BRIDGE_OUT_FEE as u64);

        // Generate bridge_id
        let bridge_id = {
            let mut data = Vec::new();
            data.extend_from_slice(b"burn:");
            data.extend_from_slice(&sender);
            data.extend_from_slice(&req.z_amount.to_be_bytes());
            data.extend_from_slice(&now_ms().to_be_bytes());
            hex::encode(zero_crypto::blake3_hash(&data))
        };

        info!(
            chain = req.dest_chain,
            token = req.token,
            amount = req.z_amount,
            fee = BRIDGE_OUT_FEE,
            sender = hex::encode(sender),
            bridge_id = bridge_id,
            "Bridge-out: Z burned (+ fee), pending release"
        );

        // Record the pending release
        let op = BridgeOperation {
            bridge_id: bridge_id.clone(),
            direction: "out".into(),
            status: "pending_release".into(),
            source_chain: req.dest_chain,
            token: req.token,
            z_amount: req.z_amount,
            attestations: 0,
            required: 2,
            created_at: now_ms(),
            dest_address: Some(req.dest_address),
            sender_pubkey: Some(hex::encode(sender)),
        };
        self.bridge_ops.lock().insert(bridge_id.clone(), op);

        Ok(Response::new(BridgeOutResponse {
            bridge_id,
            status: "pending_release".into(),
            fee: BRIDGE_OUT_FEE,
        }))
    }

    async fn get_bridge_status(
        &self,
        request: Request<GetBridgeStatusRequest>,
    ) -> Result<Response<GetBridgeStatusResponse>, Status> {
        self.check_ip_rate(&request)?;
        let req = request.into_inner();
        let ops = self.bridge_ops.lock();

        match ops.get(&req.bridge_id) {
            Some(op) => Ok(Response::new(GetBridgeStatusResponse {
                bridge_id: op.bridge_id.clone(),
                direction: op.direction.clone(),
                status: op.status.clone(),
                source_chain: op.source_chain.clone(),
                token: op.token.clone(),
                z_amount: op.z_amount,
                attestations: op.attestations,
                required: op.required,
            })),
            None => Err(Status::not_found("bridge operation not found")),
        }
    }

    async fn stream_transfers(
        &self,
        request: Request<StreamTransfersRequest>,
    ) -> Result<Response<Self::StreamTransfersStream>, Status> {
        self.check_ip_rate(&request)?;
        let req = request.into_inner();
        let from_seq = req.from_seq;

        let executor = Arc::clone(&self.executor);
        let (tx, rx) = mpsc::channel(256);

        tokio::spawn(async move {
            let mut current_seq = from_seq;
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

            loop {
                interval.tick().await;

                // Collect transfers under the lock, then send outside the lock
                let records = {
                    let exec = executor.read();
                    let total = exec.transfer_log().total_written();
                    if current_seq >= total {
                        continue;
                    }

                    let count = (total - current_seq) as usize;
                    let recent = exec.transfer_log().recent(count.min(10_000));
                    let mut batch = Vec::with_capacity(recent.len());
                    for transfer in &recent {
                        let hash = zero_crypto::blake3_hash(&transfer.to_storage_bytes());
                        batch.push(TransferRecord {
                            from: transfer.from.to_vec(),
                            to: transfer.to.to_vec(),
                            amount: transfer.amount,
                            nonce: transfer.nonce,
                            seq: current_seq,
                            tx_hash: hash.to_vec(),
                        });
                        current_seq += 1;
                    }
                    batch
                }; // lock dropped here

                for record in records {
                    if tx.send(Ok(record)).await.is_err() {
                        return; // Client disconnected
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        // No rate limiting — lightweight read, polled by explorer infrastructure
        // Piggyback rate limiter cleanup on status checks (called every few seconds by explorer)
        let now = now_ms();
        self.account_limiter.lock().cleanup(now);
        self.ip_limiter.lock().cleanup(now);

        let node = self.node.read();
        let exec = self.executor.read();

        Ok(Response::new(GetStatusResponse {
            validator_index: node.validator().index as u32,
            uptime_ms: self.start_time.elapsed().as_millis() as u64,
            dag_round: node.dag().read().current_round(),
            finalized_events: node.finalized_event_count(),
            finalized_txs: node.finalized_tx_count(),
            current_epoch: node.current_epoch(),
            account_count: exec.accounts().len() as u64,
            total_supply: exec.accounts().total_supply(),
            fee_pool: exec.fee_pool(),
            bridge_reserve: exec.bridge_reserve(),
            protocol_reserve: exec.protocol_reserve(),
            active_validators: exec.stake_store().active_count() as u32,
            total_stake: exec.stake_store().total_stake(),
            unbonding_count: exec.stake_store().unbonding_count() as u32,
            peer_count: self.peer_count,
            pending_transfers: node.validator().pending_count() as u32,
            dust_candidates: exec.dust_candidate_count() as u32,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use zero_consensus::Node;
    use zero_consensus::committee::{Committee, ValidatorInfo};
    use zero_crypto::KeyPair;
    use zero_storage::TransferExecutor;

    fn test_committee_3() -> Arc<Committee> {
        Arc::new(Committee::new(vec![
            ValidatorInfo {
                index: 0,
                public_key: [1u8; 32],
                stake: 100,
            },
            ValidatorInfo {
                index: 1,
                public_key: [2u8; 32],
                stake: 100,
            },
            ValidatorInfo {
                index: 2,
                public_key: [3u8; 32],
                stake: 100,
            },
        ]))
    }

    fn make_server() -> ZeroServer {
        let committee = test_committee_3();
        let node = Arc::new(RwLock::new(Node::new(0, committee, 10_000, 100)));
        let executor = Arc::new(RwLock::new(TransferExecutor::new(10_000)));
        ZeroServer::new(node, executor, 2, Arc::new(Mutex::new(HashMap::new())))
    }

    fn make_server_with_funding(pubkey: &[u8; 32], amount: u32) -> ZeroServer {
        let committee = test_committee_3();
        let node = Arc::new(RwLock::new(Node::new(0, committee, 10_000, 100)));
        let executor = Arc::new(RwLock::new(TransferExecutor::new(10_000)));
        executor.write().mint(pubkey, amount);
        ZeroServer::new(node, executor, 2, Arc::new(Mutex::new(HashMap::new())))
    }

    #[tokio::test]
    async fn get_balance_unknown_account() {
        let server = make_server();
        let resp = server
            .get_balance(Request::new(GetBalanceRequest {
                account: [0xAA; 32].to_vec(),
            }))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().balance, 0);
    }

    #[tokio::test]
    async fn get_balance_funded_account() {
        let pk = [0xBB; 32];
        let server = make_server_with_funding(&pk, 50_000);
        let resp = server
            .get_balance(Request::new(GetBalanceRequest {
                account: pk.to_vec(),
            }))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().balance, 50_000);
    }

    #[tokio::test]
    async fn get_balance_invalid_length() {
        let server = make_server();
        let result = server
            .get_balance(Request::new(GetBalanceRequest {
                account: vec![0x01; 16],
            }))
            .await;
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn get_account_default() {
        let server = make_server();
        let resp = server
            .get_account(Request::new(GetAccountRequest {
                account: [0xAA; 32].to_vec(),
            }))
            .await
            .unwrap();
        let acct = resp.into_inner();
        assert_eq!(acct.balance, 0);
        assert_eq!(acct.nonce, 0);
    }

    #[tokio::test]
    async fn get_account_funded() {
        let pk = [0xCC; 32];
        let server = make_server_with_funding(&pk, 100_000);
        let resp = server
            .get_account(Request::new(GetAccountRequest {
                account: pk.to_vec(),
            }))
            .await
            .unwrap();
        let acct = resp.into_inner();
        assert_eq!(acct.balance, 100_000);
        assert_eq!(acct.nonce, 0);
    }

    #[tokio::test]
    async fn get_account_invalid_length() {
        let server = make_server();
        let result = server
            .get_account(Request::new(GetAccountRequest {
                account: vec![0x01; 20],
            }))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_transfer_not_found() {
        let server = make_server();
        let resp = server
            .get_transfer(Request::new(GetTransferRequest {
                tx_hash: [0xFF; 32].to_vec(),
            }))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().status, "not_found");
    }

    #[tokio::test]
    async fn get_transfer_invalid_hash_length() {
        let server = make_server();
        let result = server
            .get_transfer(Request::new(GetTransferRequest {
                tx_hash: vec![0xFF; 16],
            }))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_history_empty() {
        let server = make_server();
        let resp = server
            .get_history(Request::new(GetHistoryRequest {
                account: [0xAA; 32].to_vec(),
                limit: 10,
            }))
            .await
            .unwrap();
        assert!(resp.into_inner().transfers.is_empty());
    }

    #[tokio::test]
    async fn get_history_invalid_account() {
        let server = make_server();
        let result = server
            .get_history(Request::new(GetHistoryRequest {
                account: vec![0x01; 5],
                limit: 10,
            }))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_invalid_from_length() {
        let server = make_server();
        let result = server
            .send(Request::new(SendRequest {
                from: vec![0x01; 16],
                to: vec![0x02; 32],
                amount: 100,
                nonce: 1,
                signature: vec![0x03; 64],
            }))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn send_invalid_to_length() {
        let server = make_server();
        let result = server
            .send(Request::new(SendRequest {
                from: vec![0x01; 32],
                to: vec![0x02; 10],
                amount: 100,
                nonce: 1,
                signature: vec![0x03; 64],
            }))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn send_invalid_signature_length() {
        let server = make_server();
        let result = server
            .send(Request::new(SendRequest {
                from: vec![0x01; 32],
                to: vec![0x02; 32],
                amount: 100,
                nonce: 1,
                signature: vec![0x03; 32],
            }))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn send_valid_signed_transfer() {
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();
        let server = make_server_with_funding(&sender.public_key(), 10_000);

        let mut tx = Transfer {
            from: sender.public_key(),
            to: receiver.public_key(),
            amount: 500,
            nonce: 1,
            signature: [0u8; 64],
        };
        tx.signature = sender.sign_transfer(&tx);

        let result = server
            .send(Request::new(SendRequest {
                from: tx.from.to_vec(),
                to: tx.to.to_vec(),
                amount: tx.amount,
                nonce: tx.nonce,
                signature: tx.signature.to_vec(),
            }))
            .await;
        assert!(result.is_ok());
        let resp = result.unwrap().into_inner();
        assert_eq!(resp.tx_hash.len(), 32);
    }

    #[tokio::test]
    async fn bridge_in_records_operation() {
        let server = make_server();
        let resp = server
            .bridge_in(Request::new(BridgeInRequest {
                source_chain: "base".into(),
                token: "USDC".into(),
                tx_hash: "0xabcdef1234567890".into(),
                zero_recipient: [0xDD; 32].to_vec(),
            }))
            .await
            .unwrap();
        let inner = resp.into_inner();
        assert!(!inner.bridge_id.is_empty());
        assert_eq!(inner.status, "pending_attestation");
        assert_eq!(inner.z_amount, 0);

        // Should be retrievable via get_bridge_status
        let status = server
            .get_bridge_status(Request::new(GetBridgeStatusRequest {
                bridge_id: inner.bridge_id.clone(),
            }))
            .await
            .unwrap();
        let s = status.into_inner();
        assert_eq!(s.bridge_id, inner.bridge_id);
        assert_eq!(s.direction, "in");
        assert_eq!(s.status, "pending_attestation");
        assert_eq!(s.source_chain, "base");
        assert_eq!(s.token, "USDC");
    }

    #[tokio::test]
    async fn bridge_in_deterministic_id() {
        let server = make_server();

        let req1 = BridgeInRequest {
            source_chain: "base".into(),
            token: "USDC".into(),
            tx_hash: "0x1111".into(),
            zero_recipient: [0xAA; 32].to_vec(),
        };
        let req2 = req1.clone();

        let resp1 = server
            .bridge_in(Request::new(req1))
            .await
            .unwrap()
            .into_inner();
        let resp2 = server
            .bridge_in(Request::new(req2))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp1.bridge_id, resp2.bridge_id);
    }

    #[tokio::test]
    async fn bridge_in_invalid_recipient() {
        let server = make_server();
        let result = server
            .bridge_in(Request::new(BridgeInRequest {
                source_chain: "base".into(),
                token: "USDC".into(),
                tx_hash: "0xabc".into(),
                zero_recipient: vec![0x01; 16],
            }))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bridge_out_zero_amount_rejected() {
        let server = make_server();
        let result = server
            .bridge_out(Request::new(BridgeOutRequest {
                dest_chain: "base".into(),
                token: "USDC".into(),
                dest_address: "0xrecipient".into(),
                z_amount: 0,
                from: vec![0x01; 32],
                signature: vec![0x02; 64],
            }))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn bridge_out_invalid_from_length() {
        let server = make_server();
        let result = server
            .bridge_out(Request::new(BridgeOutRequest {
                dest_chain: "base".into(),
                token: "USDC".into(),
                dest_address: "0xrecipient".into(),
                z_amount: 1000,
                from: vec![0x01; 20],
                signature: vec![0x02; 64],
            }))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn bridge_out_invalid_signature_length() {
        let server = make_server();
        let result = server
            .bridge_out(Request::new(BridgeOutRequest {
                dest_chain: "base".into(),
                token: "USDC".into(),
                dest_address: "0xrecipient".into(),
                z_amount: 1000,
                from: vec![0x01; 32],
                signature: vec![0x02; 32],
            }))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_bridge_status_not_found() {
        let server = make_server();
        let result = server
            .get_bridge_status(Request::new(GetBridgeStatusRequest {
                bridge_id: "nonexistent".into(),
            }))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn get_status_returns_info() {
        let server = make_server();
        let resp = server
            .get_status(Request::new(GetStatusRequest {}))
            .await
            .unwrap();
        let s = resp.into_inner();
        assert_eq!(s.validator_index, 0);
        assert!(s.uptime_ms < 5000);
        assert_eq!(s.peer_count, 2);
        assert_eq!(s.finalized_events, 0);
        assert_eq!(s.finalized_txs, 0);
    }

    #[tokio::test]
    async fn get_status_reflects_supply() {
        let pk = [0xDD; 32];
        let server = make_server_with_funding(&pk, 1_000_000);
        let resp = server
            .get_status(Request::new(GetStatusRequest {}))
            .await
            .unwrap();
        let s = resp.into_inner();
        assert_eq!(s.total_supply, 1_000_000);
        assert!(s.account_count >= 1);
    }

    #[tokio::test]
    async fn bridge_out_with_valid_signature() {
        let keypair = KeyPair::generate();
        let pk = keypair.public_key();
        let server = make_server_with_funding(&pk, 50_000);

        let burn_op = BridgeOp::Burn {
            sender: pk,
            amount: 1000,
            dest_chain: "base".into(),
            dest_address: "0xrecipient".into(),
        };
        let signing_bytes = burn_op.signing_bytes();
        let sig = keypair.sign(&signing_bytes);

        let result = server
            .bridge_out(Request::new(BridgeOutRequest {
                dest_chain: "base".into(),
                token: "USDC".into(),
                dest_address: "0xrecipient".into(),
                z_amount: 1000,
                from: pk.to_vec(),
                signature: sig.to_vec(),
            }))
            .await;
        assert!(result.is_ok());
        let resp = result.unwrap().into_inner();
        assert_eq!(resp.status, "pending_release");
        assert!(!resp.bridge_id.is_empty());

        // Verify balance was burned (amount + BRIDGE_OUT_FEE)
        let balance = server
            .get_balance(Request::new(GetBalanceRequest {
                account: pk.to_vec(),
            }))
            .await
            .unwrap()
            .into_inner()
            .balance;
        assert_eq!(balance, 50_000 - 1000 - BRIDGE_OUT_FEE); // 48,950
    }

    #[tokio::test]
    async fn bridge_out_insufficient_balance() {
        let keypair = KeyPair::generate();
        let pk = keypair.public_key();
        let server = make_server_with_funding(&pk, 500);

        let burn_op = BridgeOp::Burn {
            sender: pk,
            amount: 1000,
            dest_chain: "base".into(),
            dest_address: "0xrecipient".into(),
        };
        let signing_bytes = burn_op.signing_bytes();
        let sig = keypair.sign(&signing_bytes);

        let result = server
            .bridge_out(Request::new(BridgeOutRequest {
                dest_chain: "base".into(),
                token: "USDC".into(),
                dest_address: "0xrecipient".into(),
                z_amount: 1000,
                from: pk.to_vec(),
                signature: sig.to_vec(),
            }))
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn ip_rate_limiter_basic() {
        let mut rl = IpRateLimiter::new(10);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        for _ in 0..10 {
            assert!(rl.check(ip, 1000).is_ok());
        }
        assert!(rl.check(ip, 1000).is_err());
        // New window
        assert!(rl.check(ip, 2001).is_ok());
    }

    #[test]
    fn ip_rate_limiter_independent_ips() {
        let mut rl = IpRateLimiter::new(5);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..5 {
            rl.check(ip1, 1000).unwrap();
        }
        assert!(rl.check(ip1, 1000).is_err());
        assert!(rl.check(ip2, 1000).is_ok());
    }

    #[test]
    fn ip_rate_limiter_cleanup() {
        let mut rl = IpRateLimiter::new(10);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        rl.check(ip, 1000).unwrap();
        assert_eq!(rl.windows.len(), 1);
        rl.cleanup(20_000);
        assert_eq!(rl.windows.len(), 0);
    }

    #[tokio::test]
    async fn history_limit_capped_at_100() {
        let server = make_server();
        let resp = server
            .get_history(Request::new(GetHistoryRequest {
                account: [0xAA; 32].to_vec(),
                limit: 10_000,
            }))
            .await
            .unwrap();
        assert!(resp.into_inner().transfers.is_empty());
    }
}
