//! Parse Ethereum log events from the ZeroVault contract.
//!
//! Event ABI:
//!   Deposited(address indexed depositor, address indexed token, uint256 amount, bytes32 zeroRecipient)
//!   Released(address indexed recipient, address indexed token, uint256 amount, bytes32 bridgeId)

use crate::eip712::keccak256;

/// A parsed Deposited event from the ZeroVault contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositEvent {
    /// The depositor's Ethereum address
    pub depositor: [u8; 20],
    /// The token address (USDC or USDT)
    pub token: [u8; 20],
    /// Amount deposited (in token decimals, e.g., 6 for USDC)
    pub amount: u64,
    /// 32-byte Zero network recipient public key
    pub zero_recipient: [u8; 32],
    /// Source chain identifier
    pub source_chain: String,
    /// Source transaction hash
    pub source_tx: [u8; 32],
    /// Block number where the deposit was confirmed
    pub block_number: u64,
}

/// Event signature: keccak256("Deposited(address,address,uint256,bytes32)")
pub fn deposited_event_signature() -> [u8; 32] {
    keccak256(b"Deposited(address,address,uint256,bytes32)")
}

/// Event signature: keccak256("Released(address,address,uint256,bytes32)")
pub fn released_event_signature() -> [u8; 32] {
    keccak256(b"Released(address,address,uint256,bytes32)")
}

/// Parse a Deposited event from raw Ethereum log data.
///
/// Log structure:
///   topics[0] = event signature hash
///   topics[1] = depositor (indexed, left-padded address)
///   topics[2] = token (indexed, left-padded address)
///   data = abi.encode(amount, zeroRecipient) = 64 bytes
pub fn parse_deposit_log(
    topics: &[[u8; 32]],
    data: &[u8],
    source_chain: &str,
    source_tx: [u8; 32],
    block_number: u64,
) -> Result<DepositEvent, EventParseError> {
    // Validate topics
    if topics.len() < 3 {
        return Err(EventParseError::InsufficientTopics {
            have: topics.len(),
            need: 3,
        });
    }

    // Verify event signature
    if topics[0] != deposited_event_signature() {
        return Err(EventParseError::WrongEventSignature);
    }

    // Data should be exactly 64 bytes: uint256 amount (32) + bytes32 zeroRecipient (32)
    if data.len() < 64 {
        return Err(EventParseError::InsufficientData {
            have: data.len(),
            need: 64,
        });
    }

    // Extract depositor from topics[1] (last 20 bytes of 32-byte topic)
    let mut depositor = [0u8; 20];
    depositor.copy_from_slice(&topics[1][12..]);

    // Extract token from topics[2]
    let mut token = [0u8; 20];
    token.copy_from_slice(&topics[2][12..]);

    // Extract amount from data[0..32] (uint256, big-endian)
    // For USDC/USDT amounts, we only need u64 (max ~18.4 quintillion)
    let amount = u64::from_be_bytes(data[24..32].try_into().unwrap());

    // Extract zeroRecipient from data[32..64]
    let mut zero_recipient = [0u8; 32];
    zero_recipient.copy_from_slice(&data[32..64]);

    Ok(DepositEvent {
        depositor,
        token,
        amount,
        zero_recipient,
        source_chain: source_chain.to_string(),
        source_tx,
        block_number,
    })
}

/// A parsed Released event from the ZeroVault contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseEvent {
    /// The recipient's Ethereum address
    pub recipient: [u8; 20],
    /// The token address
    pub token: [u8; 20],
    /// Amount released (in token decimals)
    pub amount: u64,
    /// Bridge operation ID
    pub bridge_id: [u8; 32],
    /// Source chain identifier
    pub chain: String,
    /// Transaction hash of the release
    pub tx_hash: [u8; 32],
    /// Block number where the release was confirmed
    pub block_number: u64,
}

/// Parse a Released event from raw Ethereum log data.
///
/// Log structure:
///   topics[0] = event signature hash
///   topics[1] = recipient (indexed, left-padded address)
///   topics[2] = token (indexed, left-padded address)
///   data = abi.encode(amount, bridgeId) = 64 bytes
pub fn parse_release_log(
    topics: &[[u8; 32]],
    data: &[u8],
    chain: &str,
    tx_hash: [u8; 32],
    block_number: u64,
) -> Result<ReleaseEvent, EventParseError> {
    if topics.len() < 3 {
        return Err(EventParseError::InsufficientTopics {
            have: topics.len(),
            need: 3,
        });
    }

    if topics[0] != released_event_signature() {
        return Err(EventParseError::WrongEventSignature);
    }

    if data.len() < 64 {
        return Err(EventParseError::InsufficientData {
            have: data.len(),
            need: 64,
        });
    }

    // Extract recipient from topics[1] (last 20 bytes)
    let mut recipient = [0u8; 20];
    recipient.copy_from_slice(&topics[1][12..]);

    // Extract token from topics[2]
    let mut token = [0u8; 20];
    token.copy_from_slice(&topics[2][12..]);

    // Extract amount from data[0..32] (uint256, big-endian)
    let amount = u64::from_be_bytes(data[24..32].try_into().unwrap());

    // Extract bridgeId from data[32..64]
    let mut bridge_id = [0u8; 32];
    bridge_id.copy_from_slice(&data[32..64]);

    Ok(ReleaseEvent {
        recipient,
        token,
        amount,
        bridge_id,
        chain: chain.to_string(),
        tx_hash,
        block_number,
    })
}

/// Convert a DepositEvent to a BridgeOp::Mint for the Zero chain.
impl DepositEvent {
    /// Convert deposit amount to Z units.
    /// 1 USDC (6 decimals) = 100 Z units.
    /// So: z_amount = usdc_amount * 100 / 1_000_000 = usdc_amount / 10_000
    /// But we track Z in units where 1 unit = 0.01 Z.
    /// So: 1 USDC = 1_000_000 raw → 100 Z → 10_000 units.
    /// z_units = raw_amount / 100 (for 6-decimal tokens)
    pub fn to_z_units(&self, token_decimals: u8) -> u64 {
        match token_decimals {
            6 => self.amount / 100, // USDC/USDT: 1_000_000 raw = 10_000 Z units = 100 Z
            18 => self.amount / 10_000_000_000_000_000, // DAI-like
            _ => self.amount,       // Fallback, should not happen
        }
    }

    /// Generate a deterministic bridge ID from the source chain event.
    pub fn bridge_id(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(self.source_chain.as_bytes());
        data.extend_from_slice(&self.source_tx);
        data.extend_from_slice(&self.block_number.to_be_bytes());
        keccak256(&data)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EventParseError {
    #[error("insufficient topics: have {have}, need {need}")]
    InsufficientTopics { have: usize, need: usize },
    #[error("wrong event signature")]
    WrongEventSignature,
    #[error("insufficient data: have {have} bytes, need {need}")]
    InsufficientData { have: usize, need: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_log() -> (Vec<[u8; 32]>, Vec<u8>) {
        let event_sig = deposited_event_signature();

        // depositor = 0xA11CE...
        let mut topic1 = [0u8; 32];
        topic1[31] = 0xCE;
        topic1[30] = 0x1A;

        // token = 0x1111...
        let mut topic2 = [0u8; 32];
        topic2[12..].fill(0x11);

        let topics = vec![event_sig, topic1, topic2];

        // data: amount = 1_000_000 (1 USDC), zeroRecipient = 0x1234...
        let mut data = vec![0u8; 64];
        // amount in last 8 bytes of first 32-byte word
        let amount_bytes = 1_000_000u64.to_be_bytes();
        data[24..32].copy_from_slice(&amount_bytes);
        // zeroRecipient
        data[32..64].fill(0x12);

        (topics, data)
    }

    #[test]
    fn parse_valid_deposit() {
        let (topics, data) = make_test_log();
        let tx_hash = [0xAB; 32];

        let event = parse_deposit_log(&topics, &data, "base", tx_hash, 12345).unwrap();

        assert_eq!(event.amount, 1_000_000);
        assert_eq!(event.source_chain, "base");
        assert_eq!(event.source_tx, tx_hash);
        assert_eq!(event.block_number, 12345);
        assert_eq!(event.zero_recipient, [0x12; 32]);
        // Token should be 0x1111...
        assert_eq!(event.token, [0x11; 20]);
    }

    #[test]
    fn insufficient_topics_rejected() {
        let (topics, data) = make_test_log();
        let result = parse_deposit_log(&topics[..2], &data, "base", [0; 32], 0);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_event_signature_rejected() {
        let (mut topics, data) = make_test_log();
        topics[0] = [0xFF; 32]; // Wrong signature
        let result = parse_deposit_log(&topics, &data, "base", [0; 32], 0);
        assert!(matches!(result, Err(EventParseError::WrongEventSignature)));
    }

    #[test]
    fn insufficient_data_rejected() {
        let (topics, _) = make_test_log();
        let short_data = vec![0u8; 32]; // Only 32 bytes, need 64
        let result = parse_deposit_log(&topics, &short_data, "base", [0; 32], 0);
        assert!(matches!(
            result,
            Err(EventParseError::InsufficientData { .. })
        ));
    }

    #[test]
    fn z_unit_conversion_usdc() {
        let (topics, data) = make_test_log();
        let event = parse_deposit_log(&topics, &data, "base", [0; 32], 0).unwrap();

        // 1_000_000 raw USDC (6 decimals) = 1 USDC = 100 Z = 10_000 Z units
        assert_eq!(event.to_z_units(6), 10_000);
    }

    #[test]
    fn z_unit_conversion_large_amount() {
        let mut data = vec![0u8; 64];
        let amount_bytes = 100_000_000u64.to_be_bytes(); // 100 USDC
        data[24..32].copy_from_slice(&amount_bytes);
        data[32..64].fill(0x12);

        let (topics, _) = make_test_log();
        let event = parse_deposit_log(&topics, &data, "base", [0; 32], 0).unwrap();

        // 100 USDC = 10,000 Z = 1,000,000 Z units
        assert_eq!(event.to_z_units(6), 1_000_000);
    }

    #[test]
    fn bridge_id_is_deterministic() {
        let (topics, data) = make_test_log();
        let event = parse_deposit_log(&topics, &data, "base", [0xAB; 32], 100).unwrap();

        let id1 = event.bridge_id();
        let id2 = event.bridge_id();
        assert_eq!(id1, id2);
        assert_ne!(id1, [0u8; 32]); // Non-zero
    }

    #[test]
    fn different_txs_different_bridge_ids() {
        let (topics, data) = make_test_log();
        let event1 = parse_deposit_log(&topics, &data, "base", [0xAB; 32], 100).unwrap();
        let event2 = parse_deposit_log(&topics, &data, "base", [0xCD; 32], 100).unwrap();

        assert_ne!(event1.bridge_id(), event2.bridge_id());
    }

    #[test]
    fn event_signatures_are_correct() {
        // Verify the event signatures are keccak256 of the correct ABI strings
        let dep_sig = deposited_event_signature();
        let rel_sig = released_event_signature();
        assert_ne!(dep_sig, rel_sig);
        assert_ne!(dep_sig, [0u8; 32]);
    }

    fn make_test_release_log() -> (Vec<[u8; 32]>, Vec<u8>) {
        let event_sig = released_event_signature();

        // recipient
        let mut topic1 = [0u8; 32];
        topic1[31] = 0xBB;
        topic1[30] = 0x2A;

        // token
        let mut topic2 = [0u8; 32];
        topic2[12..].fill(0x22);

        let topics = vec![event_sig, topic1, topic2];

        // data: amount = 5_000_000 (5 USDC), bridgeId = 0x33...
        let mut data = vec![0u8; 64];
        let amount_bytes = 5_000_000u64.to_be_bytes();
        data[24..32].copy_from_slice(&amount_bytes);
        data[32..64].fill(0x33);

        (topics, data)
    }

    #[test]
    fn parse_valid_release() {
        let (topics, data) = make_test_release_log();
        let tx_hash = [0xCD; 32];

        let event = parse_release_log(&topics, &data, "base", tx_hash, 99999).unwrap();

        assert_eq!(event.amount, 5_000_000);
        assert_eq!(event.chain, "base");
        assert_eq!(event.tx_hash, tx_hash);
        assert_eq!(event.block_number, 99999);
        assert_eq!(event.bridge_id, [0x33; 32]);
        assert_eq!(event.token, [0x22; 20]);
    }

    #[test]
    fn release_wrong_signature_rejected() {
        let (mut topics, data) = make_test_release_log();
        topics[0] = deposited_event_signature(); // Wrong event type
        let result = parse_release_log(&topics, &data, "base", [0; 32], 0);
        assert!(matches!(result, Err(EventParseError::WrongEventSignature)));
    }

    #[test]
    fn release_insufficient_data_rejected() {
        let (topics, _) = make_test_release_log();
        let short_data = vec![0u8; 32];
        let result = parse_release_log(&topics, &short_data, "base", [0; 32], 0);
        assert!(matches!(
            result,
            Err(EventParseError::InsufficientData { .. })
        ));
    }
}
