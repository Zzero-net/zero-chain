//! Minimal Ethereum JSON-RPC client for watching vault events and submitting transactions.
//!
//! Uses raw `eth_getLogs` / `eth_blockNumber` / `eth_sendRawTransaction` calls via reqwest.
//! EIP-1559 transaction encoding uses alloy-rlp. This avoids pulling in the full ethers/alloy
//! stack for what is a narrow set of RPC calls.

use alloy_rlp::Encodable;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::eip712::{keccak256, verifying_key_to_address};
use crate::events::{self, DepositEvent, ReleaseEvent};

/// Ethereum JSON-RPC client.
pub struct EthRpc {
    client: reqwest::Client,
    rpc_url: String,
    chain_name: String,
}

/// A raw Ethereum log entry from `eth_getLogs`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub transaction_hash: String,
    #[serde(default)]
    pub removed: bool,
}

/// JSON-RPC request envelope.
#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    method: &'static str,
    params: serde_json::Value,
    id: u64,
}

/// JSON-RPC response envelope.
#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc { code: i64, message: String },
    #[error("unexpected response format")]
    BadResponse,
    #[error("hex decode error: {0}")]
    HexDecode(String),
}

impl EthRpc {
    pub fn new(rpc_url: &str, chain_name: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            rpc_url: rpc_url.to_string(),
            chain_name: chain_name.to_string(),
        }
    }

    /// Get the latest block number.
    pub async fn block_number(&self) -> Result<u64, RpcError> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_blockNumber",
            params: serde_json::json!([]),
            id: 1,
        };

        let resp: JsonRpcResponse<String> = self
            .client
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.error {
            return Err(RpcError::JsonRpc {
                code: err.code,
                message: err.message,
            });
        }

        let hex_str = resp.result.ok_or(RpcError::BadResponse)?;
        parse_hex_u64(&hex_str)
    }

    /// Fetch logs matching the Deposited event from a vault contract.
    ///
    /// Automatically chunks into batches of 10 blocks to stay within Alchemy
    /// free-tier `eth_getLogs` limits on Arbitrum.
    pub async fn get_deposit_logs(
        &self,
        vault_address: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<RawLog>, RpcError> {
        const MAX_BLOCK_RANGE: u64 = 10;
        let event_sig = format!("0x{}", hex::encode(events::deposited_event_signature()));
        let mut all_logs = Vec::new();

        let mut chunk_from = from_block;
        while chunk_from <= to_block {
            let chunk_to = std::cmp::min(chunk_from + MAX_BLOCK_RANGE - 1, to_block);

            let req = JsonRpcRequest {
                jsonrpc: "2.0",
                method: "eth_getLogs",
                params: serde_json::json!([{
                    "address": format!("0x{}", vault_address),
                    "topics": [event_sig],
                    "fromBlock": format!("0x{:x}", chunk_from),
                    "toBlock": format!("0x{:x}", chunk_to),
                }]),
                id: 1,
            };

            let resp: JsonRpcResponse<Vec<RawLog>> = self
                .client
                .post(&self.rpc_url)
                .json(&req)
                .send()
                .await?
                .json()
                .await?;

            if let Some(err) = resp.error {
                return Err(RpcError::JsonRpc {
                    code: err.code,
                    message: err.message,
                });
            }

            let logs = resp.result.ok_or(RpcError::BadResponse)?;
            all_logs.extend(logs);

            chunk_from = chunk_to + 1;
        }

        debug!(chain = %self.chain_name, count = all_logs.len(), "fetched deposit logs");
        Ok(all_logs)
    }

    /// Parse a raw log into a DepositEvent.
    pub fn parse_deposit_log(&self, log: &RawLog) -> Result<DepositEvent, String> {
        if log.removed {
            return Err("log was removed (reorg)".into());
        }

        let topics = parse_topics(&log.topics)?;
        let data = parse_hex_bytes(&log.data).map_err(|e| format!("bad data hex: {}", e))?;
        let block =
            parse_hex_u64(&log.block_number).map_err(|e| format!("bad block number: {}", e))?;
        let tx_hash =
            parse_hex_bytes32(&log.transaction_hash).map_err(|e| format!("bad tx hash: {}", e))?;

        events::parse_deposit_log(&topics, &data, &self.chain_name, tx_hash, block)
            .map_err(|e| format!("parse error: {}", e))
    }

    /// Fetch logs matching the Released event from a vault contract.
    ///
    /// Automatically chunks into batches of 10 blocks to stay within Alchemy
    /// free-tier `eth_getLogs` limits on Arbitrum.
    pub async fn get_release_logs(
        &self,
        vault_address: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<RawLog>, RpcError> {
        const MAX_BLOCK_RANGE: u64 = 10;
        let event_sig = format!("0x{}", hex::encode(events::released_event_signature()));
        let mut all_logs = Vec::new();

        let mut chunk_from = from_block;
        while chunk_from <= to_block {
            let chunk_to = std::cmp::min(chunk_from + MAX_BLOCK_RANGE - 1, to_block);

            let req = JsonRpcRequest {
                jsonrpc: "2.0",
                method: "eth_getLogs",
                params: serde_json::json!([{
                    "address": format!("0x{}", vault_address),
                    "topics": [event_sig],
                    "fromBlock": format!("0x{:x}", chunk_from),
                    "toBlock": format!("0x{:x}", chunk_to),
                }]),
                id: 1,
            };

            let resp: JsonRpcResponse<Vec<RawLog>> = self
                .client
                .post(&self.rpc_url)
                .json(&req)
                .send()
                .await?
                .json()
                .await?;

            if let Some(err) = resp.error {
                return Err(RpcError::JsonRpc {
                    code: err.code,
                    message: err.message,
                });
            }

            let logs = resp.result.ok_or(RpcError::BadResponse)?;
            all_logs.extend(logs);

            chunk_from = chunk_to + 1;
        }

        debug!(chain = %self.chain_name, count = all_logs.len(), "fetched release logs");
        Ok(all_logs)
    }

    /// Parse a raw log into a ReleaseEvent.
    pub fn parse_release_log(&self, log: &RawLog) -> Result<ReleaseEvent, String> {
        if log.removed {
            return Err("log was removed (reorg)".into());
        }

        let topics = parse_topics(&log.topics)?;
        let data = parse_hex_bytes(&log.data).map_err(|e| format!("bad data hex: {}", e))?;
        let block =
            parse_hex_u64(&log.block_number).map_err(|e| format!("bad block number: {}", e))?;
        let tx_hash =
            parse_hex_bytes32(&log.transaction_hash).map_err(|e| format!("bad tx hash: {}", e))?;

        events::parse_release_log(&topics, &data, &self.chain_name, tx_hash, block)
            .map_err(|e| format!("parse error: {}", e))
    }

    /// Submit a pause() transaction to the vault contract.
    /// Returns the transaction hash.
    pub async fn send_pause(
        &self,
        chain_id: u64,
        vault_address: &[u8; 20],
        from_key: &[u8; 32],
    ) -> Result<[u8; 32], RpcError> {
        let signing_key = SigningKey::from_bytes(from_key.into())
            .map_err(|e| RpcError::HexDecode(format!("invalid private key: {}", e)))?;
        let sender_address = verifying_key_to_address(signing_key.verifying_key());

        let nonce = self.get_nonce(&sender_address).await?;
        let base_fee = self.gas_price().await?;

        let priority_fee: u64 = 2_000_000_000; // 2 gwei — higher priority for pause
        let max_fee = base_fee.saturating_mul(3).saturating_add(priority_fee);
        let gas_limit: u64 = 100_000; // pause() is cheap

        // pause() calldata: just the 4-byte selector
        let calldata = pause_selector().to_vec();

        let unsigned_payload = Eip1559Unsigned {
            chain_id,
            nonce,
            max_priority_fee_per_gas: priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit,
            to: *vault_address,
            value: 0,
            data: calldata.clone(),
        };

        let mut unsigned_rlp = Vec::new();
        unsigned_payload.encode(&mut unsigned_rlp);
        let mut to_sign = vec![0x02u8];
        to_sign.extend_from_slice(&unsigned_rlp);

        let tx_hash = keccak256(&to_sign);
        let (sig, recovery_id) = signing_key
            .sign_prehash_recoverable(&tx_hash)
            .map_err(|e| RpcError::HexDecode(format!("signing failed: {}", e)))?;

        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        let v = recovery_id.to_byte();
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..];

        let signed = Eip1559Signed {
            chain_id,
            nonce,
            max_priority_fee_per_gas: priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit,
            to: *vault_address,
            value: 0,
            data: calldata,
            v,
            r: r.try_into().unwrap(),
            s: s.try_into().unwrap(),
        };

        let mut signed_rlp = Vec::new();
        signed.encode(&mut signed_rlp);
        let mut raw_tx = vec![0x02u8];
        raw_tx.extend_from_slice(&signed_rlp);

        let raw_hex = format!("0x{}", hex::encode(&raw_tx));

        info!(
            chain = %self.chain_name,
            nonce,
            "submitting EMERGENCY PAUSE transaction"
        );

        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_sendRawTransaction",
            params: serde_json::json!([raw_hex]),
            id: 1,
        };

        let resp: JsonRpcResponse<String> = self
            .client
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.error {
            return Err(RpcError::JsonRpc {
                code: err.code,
                message: err.message,
            });
        }

        let tx_hash_hex = resp.result.ok_or(RpcError::BadResponse)?;
        parse_hex_bytes32(&tx_hash_hex).map_err(RpcError::HexDecode)
    }

    /// Get the transaction count (nonce) for an address.
    pub async fn get_nonce(&self, address: &[u8; 20]) -> Result<u64, RpcError> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_getTransactionCount",
            params: serde_json::json!([format!("0x{}", hex::encode(address)), "pending"]),
            id: 1,
        };

        let resp: JsonRpcResponse<String> = self
            .client
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.error {
            return Err(RpcError::JsonRpc {
                code: err.code,
                message: err.message,
            });
        }

        let hex_str = resp.result.ok_or(RpcError::BadResponse)?;
        parse_hex_u64(&hex_str)
    }

    /// Get the current base fee (gas price).
    pub async fn gas_price(&self) -> Result<u64, RpcError> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_gasPrice",
            params: serde_json::json!([]),
            id: 1,
        };

        let resp: JsonRpcResponse<String> = self
            .client
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.error {
            return Err(RpcError::JsonRpc {
                code: err.code,
                message: err.message,
            });
        }

        let hex_str = resp.result.ok_or(RpcError::BadResponse)?;
        parse_hex_u64(&hex_str)
    }

    /// Submit a signed release transaction to the vault contract.
    /// Returns the transaction hash.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_release(
        &self,
        chain_id: u64,
        vault_address: &[u8; 20],
        token: &[u8; 20],
        amount: u64,
        recipient: &[u8; 20],
        bridge_id: &[u8; 32],
        signatures: &[u8],
        from_key: &[u8; 32],
    ) -> Result<[u8; 32], RpcError> {
        let signing_key = SigningKey::from_bytes(from_key.into())
            .map_err(|e| RpcError::HexDecode(format!("invalid private key: {}", e)))?;
        let sender_address = verifying_key_to_address(signing_key.verifying_key());

        // Fetch nonce and gas price
        let nonce = self.get_nonce(&sender_address).await?;
        let base_fee = self.gas_price().await?;

        // EIP-1559 gas params: priority fee 1.5 gwei, max fee = 2 * base + priority
        let priority_fee: u64 = 1_500_000_000; // 1.5 gwei
        let max_fee = base_fee.saturating_mul(2).saturating_add(priority_fee);
        let gas_limit: u64 = 500_000;

        // Encode release() calldata
        let calldata = encode_release_calldata(token, amount, recipient, bridge_id, signatures);

        // Build unsigned EIP-1559 transaction for signing
        let unsigned_payload = Eip1559Unsigned {
            chain_id,
            nonce,
            max_priority_fee_per_gas: priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit,
            to: *vault_address,
            value: 0,
            data: calldata.clone(),
        };

        // RLP encode the unsigned payload for signing: 0x02 || rlp(fields)
        let mut unsigned_rlp = Vec::new();
        unsigned_payload.encode(&mut unsigned_rlp);
        let mut to_sign = vec![0x02u8];
        to_sign.extend_from_slice(&unsigned_rlp);

        // Sign the transaction hash
        let tx_hash = keccak256(&to_sign);
        let (sig, recovery_id) = signing_key
            .sign_prehash_recoverable(&tx_hash)
            .map_err(|e| RpcError::HexDecode(format!("signing failed: {}", e)))?;

        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        let v = recovery_id.to_byte(); // 0 or 1 for EIP-1559 (not +27)
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..];

        // Build signed transaction
        let signed = Eip1559Signed {
            chain_id,
            nonce,
            max_priority_fee_per_gas: priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit,
            to: *vault_address,
            value: 0,
            data: calldata,
            v,
            r: r.try_into().unwrap(),
            s: s.try_into().unwrap(),
        };

        let mut signed_rlp = Vec::new();
        signed.encode(&mut signed_rlp);
        let mut raw_tx = vec![0x02u8]; // EIP-1559 type prefix
        raw_tx.extend_from_slice(&signed_rlp);

        let raw_hex = format!("0x{}", hex::encode(&raw_tx));

        info!(
            chain = %self.chain_name,
            nonce,
            gas_limit,
            max_fee_gwei = max_fee / 1_000_000_000,
            calldata_len = raw_tx.len(),
            "submitting release transaction"
        );

        // Submit via eth_sendRawTransaction
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_sendRawTransaction",
            params: serde_json::json!([raw_hex]),
            id: 1,
        };

        let resp: JsonRpcResponse<String> = self
            .client
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.error {
            return Err(RpcError::JsonRpc {
                code: err.code,
                message: err.message,
            });
        }

        let tx_hash_hex = resp.result.ok_or(RpcError::BadResponse)?;
        parse_hex_bytes32(&tx_hash_hex).map_err(RpcError::HexDecode)
    }
}

// === EIP-1559 Transaction Encoding ===

/// Unsigned EIP-1559 transaction fields (for signing).
struct Eip1559Unsigned {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u64,
    max_fee_per_gas: u64,
    gas_limit: u64,
    to: [u8; 20],
    value: u64,
    data: Vec<u8>,
    // access_list is always empty — alloy-rlp encodes it as empty list via the
    // Encodable implementation below.
}

/// Manually implement to append empty access list.
impl Encodable for Eip1559Unsigned {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_payload_len(),
        }
        .encode(out);
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.data.encode(out);
        // Empty access list
        alloy_rlp::Header {
            list: true,
            payload_length: 0,
        }
        .encode(out);
    }

    fn length(&self) -> usize {
        let payload = self.rlp_payload_len();
        alloy_rlp::length_of_length(payload) + 1 + payload
    }
}

impl Eip1559Unsigned {
    fn rlp_payload_len(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.data.length()
            + 1 // empty access list: 0xc0 (1 byte)
    }
}

/// Signed EIP-1559 transaction fields.
struct Eip1559Signed {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u64,
    max_fee_per_gas: u64,
    gas_limit: u64,
    to: [u8; 20],
    value: u64,
    data: Vec<u8>,
    v: u8,
    r: [u8; 32],
    s: [u8; 32],
}

impl Encodable for Eip1559Signed {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let payload = self.rlp_payload_len();
        alloy_rlp::Header {
            list: true,
            payload_length: payload,
        }
        .encode(out);
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.data.encode(out);
        // Empty access list
        alloy_rlp::Header {
            list: true,
            payload_length: 0,
        }
        .encode(out);
        // Signature: v as single byte, r and s as 32-byte big-endian with leading zeros stripped
        self.v.encode(out);
        encode_u256_bytes(&self.r, out);
        encode_u256_bytes(&self.s, out);
    }

    fn length(&self) -> usize {
        let payload = self.rlp_payload_len();
        alloy_rlp::length_of_length(payload) + 1 + payload
    }
}

impl Eip1559Signed {
    fn rlp_payload_len(&self) -> usize {
        self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.data.length()
            + 1 // empty access list
            + self.v.length()
            + rlp_u256_len(&self.r)
            + rlp_u256_len(&self.s)
    }
}

/// RLP-encode a 32-byte big-endian integer, stripping leading zeros.
fn encode_u256_bytes(bytes: &[u8; 32], out: &mut dyn alloy_rlp::BufMut) {
    let stripped = strip_leading_zeros(bytes);
    stripped.encode(out);
}

/// Calculate RLP length for a 32-byte big-endian integer.
fn rlp_u256_len(bytes: &[u8; 32]) -> usize {
    let stripped = strip_leading_zeros(bytes);
    stripped.length()
}

/// Strip leading zeros from a byte slice.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

// === ABI Encoding ===

/// Compute the pause() function selector.
pub fn pause_selector() -> [u8; 4] {
    let hash = keccak256(b"pause()");
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&hash[..4]);
    sel
}

/// Compute the release() function selector.
pub fn release_selector() -> [u8; 4] {
    let hash = keccak256(b"release(address,uint256,address,bytes32,bytes)");
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&hash[..4]);
    sel
}

/// ABI-encode the calldata for `release(address,uint256,address,bytes32,bytes)`.
pub fn encode_release_calldata(
    token: &[u8; 20],
    amount: u64,
    recipient: &[u8; 20],
    bridge_id: &[u8; 32],
    signatures: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 * 6 + signatures.len());

    // Function selector
    data.extend_from_slice(&release_selector());

    // Word 0: address token (left-padded)
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(token);
    data.extend_from_slice(&word);

    // Word 1: uint256 amount (left-padded)
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&word);

    // Word 2: address recipient (left-padded)
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(recipient);
    data.extend_from_slice(&word);

    // Word 3: bytes32 bridgeId
    data.extend_from_slice(bridge_id);

    // Word 4: offset to bytes data (5 * 32 = 160 = 0xa0)
    let mut word = [0u8; 32];
    word[31] = 0xa0;
    data.extend_from_slice(&word);

    // Dynamic bytes: length prefix
    let mut word = [0u8; 32];
    let sig_len = signatures.len() as u64;
    word[24..].copy_from_slice(&sig_len.to_be_bytes());
    data.extend_from_slice(&word);

    // Dynamic bytes: data (right-padded to 32-byte boundary)
    data.extend_from_slice(signatures);
    let padding = (32 - (signatures.len() % 32)) % 32;
    data.extend(std::iter::repeat_n(0u8, padding));

    data
}

/// Parse hex topics from string array to bytes32 array.
fn parse_topics(topics: &[String]) -> Result<Vec<[u8; 32]>, String> {
    topics.iter().map(|t| parse_hex_bytes32(t)).collect()
}

/// Parse a 0x-prefixed hex string to a bytes32.
fn parse_hex_bytes32(s: &str) -> Result<[u8; 32], String> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a 0x-prefixed hex string to bytes.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(clean).map_err(|e| e.to_string())
}

/// Parse a 0x-prefixed hex string to u64.
fn parse_hex_u64(s: &str) -> Result<u64, RpcError> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(clean, 16).map_err(|e| RpcError::HexDecode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_u64_works() {
        assert_eq!(parse_hex_u64("0x1a").unwrap(), 26);
        assert_eq!(parse_hex_u64("0xff").unwrap(), 255);
        assert_eq!(parse_hex_u64("14a34").unwrap(), 84532);
    }

    #[test]
    fn parse_hex_bytes32_works() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_hex_bytes32(hex).unwrap();
        assert_eq!(result[31], 1);
        assert_eq!(result[0], 0);
    }

    #[test]
    fn parse_topics_works() {
        let topics = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        ];
        let result = parse_topics(&topics).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0][31], 1);
        assert_eq!(result[1][31], 2);
    }

    #[test]
    fn release_selector_matches_solidity() {
        // keccak256("release(address,uint256,address,bytes32,bytes)") first 4 bytes
        let sel = release_selector();
        // Verify it's deterministic and 4 bytes
        assert_eq!(sel.len(), 4);
        // Verify against known value: compute fresh
        let hash = keccak256(b"release(address,uint256,address,bytes32,bytes)");
        assert_eq!(&sel[..], &hash[..4]);
    }

    #[test]
    fn abi_encode_release_calldata_structure() {
        let token = [0xAA; 20];
        let amount = 1_000_000u64; // 1 USDC
        let recipient = [0xBB; 20];
        let bridge_id = [0xCC; 32];
        let signatures = vec![0xDD; 130]; // 2 × 65-byte sigs

        let data = encode_release_calldata(&token, amount, &recipient, &bridge_id, &signatures);

        // 4 (selector) + 5*32 (fixed params) + 32 (length) + 160 (2*65 padded to 160) = 356
        assert_eq!(data.len(), 4 + 32 * 5 + 32 + 160);

        // Selector is first 4 bytes
        assert_eq!(&data[..4], &release_selector());

        // Token address at offset 4, left-padded
        assert_eq!(&data[4 + 12..4 + 32], &[0xAA; 20]);

        // Amount at offset 36, left-padded
        assert_eq!(data[4 + 32 + 24..4 + 32 + 32], amount.to_be_bytes());

        // Recipient at offset 68, left-padded
        assert_eq!(&data[4 + 64 + 12..4 + 64 + 32], &[0xBB; 20]);

        // BridgeId at offset 100
        assert_eq!(&data[4 + 96..4 + 128], &[0xCC; 32]);

        // Offset pointer at word 4: 0xa0 = 160
        assert_eq!(data[4 + 128 + 31], 0xa0);

        // Length of signatures at word 5: 130
        let sig_len = u64::from_be_bytes(data[4 + 160 + 24..4 + 160 + 32].try_into().unwrap());
        assert_eq!(sig_len, 130);
    }

    #[test]
    fn rlp_unsigned_tx_starts_with_list_header() {
        let tx = Eip1559Unsigned {
            chain_id: 84532, // Base Sepolia
            nonce: 0,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 500_000,
            to: [0xAA; 20],
            value: 0,
            data: vec![0x01, 0x02, 0x03],
        };

        let mut buf = Vec::new();
        tx.encode(&mut buf);

        // First byte should be 0xc0+ or 0xf8+ (RLP list header)
        assert!(
            buf[0] >= 0xc0,
            "expected RLP list header, got 0x{:02x}",
            buf[0]
        );
    }

    #[test]
    fn strip_leading_zeros_works() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 2]), &[1, 2]);
        assert_eq!(strip_leading_zeros(&[0, 0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_leading_zeros(&[1, 2, 3]), &[1, 2, 3]);
    }

    #[test]
    fn signed_tx_encodes_without_panic() {
        let tx = Eip1559Signed {
            chain_id: 84532,
            nonce: 42,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 500_000,
            to: [0xAA; 20],
            value: 0,
            data: encode_release_calldata(
                &[0xBB; 20],
                1000,
                &[0xCC; 20],
                &[0xDD; 32],
                &[0xEE; 130],
            ),
            v: 1,
            r: [0x11; 32],
            s: [0x22; 32],
        };

        let mut buf = Vec::new();
        tx.encode(&mut buf);

        // Should produce a valid RLP list
        assert!(buf[0] >= 0xc0);
        assert!(
            buf.len() > 100,
            "signed tx should be >100 bytes, got {}",
            buf.len()
        );
    }
}
