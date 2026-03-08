//! Trinity Validator system — controls mint/burn of Z tokens.
//!
//! Bridge operations (minting Z for deposited USDC/USDT, burning Z for withdrawals)
//! are controlled by the 3 Trinity Validators, NOT the full consensus validator set.
//!
//! Design:
//!   - Exactly 3 Trinity Validators (trusted parties) control bridge operations
//!   - 2-of-3 multisig required for any mint or burn
//!   - Trinity Validator keys are separate from consensus validator keys
//!   - Trinity Validators are the first validators on the network
//!   - Only Trinity Validators can issue/redeem USDC/USDT for Z
//!   - Trinity Validators can be rotated by 2-of-3 agreement
//!
//! This separates concerns:
//!   - Consensus validators (permissionless, up to 1024): order transactions
//!   - Trinity Validators (3 trusted parties): control money flow in/out

use std::collections::HashSet;

use ed25519_dalek::{Signature as DalekSig, VerifyingKey};
use zero_types::PubKey;

/// Trinity Validator configuration and state.
pub struct TrinityValidatorSet {
    /// The 3 Trinity Validator public keys (Ed25519).
    validators: [PubKey; 3],
    /// Set for O(1) lookup.
    validator_set: HashSet<PubKey>,
    /// Number of signatures required (always 2 for 2-of-3).
    pub threshold: usize,
}

/// A bridge attestation signed by Trinity Validators.
#[derive(Debug, Clone)]
pub struct BridgeAttestation {
    /// Which operation this attests to.
    pub operation: BridgeOp,
    /// Trinity Validator signatures collected so far: (validator_pubkey, signature).
    pub signatures: Vec<(PubKey, [u8; 64])>,
}

/// A bridge operation (mint or burn).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeOp {
    /// Mint Z tokens (bridge-in): stablecoins locked on source chain.
    Mint {
        /// Recipient Zero public key.
        recipient: PubKey,
        /// Amount in Z units to mint.
        amount: u64,
        /// Source chain identifier ("base" or "arbitrum").
        source_chain: String,
        /// Source chain transaction hash (hex).
        source_tx: String,
    },
    /// Burn Z tokens (bridge-out): release stablecoins on destination chain.
    Burn {
        /// Sender Zero public key (whose Z is being burned).
        sender: PubKey,
        /// Amount in Z units to burn.
        amount: u64,
        /// Destination chain identifier.
        dest_chain: String,
        /// Destination address on the target chain.
        dest_address: String,
    },
}

impl BridgeOp {
    /// Canonical signing bytes for Ed25519 attestation.
    /// Format: "ZERO-BRIDGE:" || op_type || ":" || fields
    pub fn signing_bytes(&self) -> Vec<u8> {
        match self {
            BridgeOp::Mint {
                recipient,
                amount,
                source_chain,
                source_tx,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"ZERO-BRIDGE:MINT:");
                buf.extend_from_slice(recipient);
                buf.extend_from_slice(&amount.to_be_bytes());
                buf.extend_from_slice(source_chain.as_bytes());
                buf.push(b':');
                buf.extend_from_slice(source_tx.as_bytes());
                buf
            }
            BridgeOp::Burn {
                sender,
                amount,
                dest_chain,
                dest_address,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"ZERO-BRIDGE:BURN:");
                buf.extend_from_slice(sender);
                buf.extend_from_slice(&amount.to_be_bytes());
                buf.extend_from_slice(dest_chain.as_bytes());
                buf.push(b':');
                buf.extend_from_slice(dest_address.as_bytes());
                buf
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("not a Trinity Validator: {0:?}")]
    NotTrinityValidator(PubKey),
    #[error("duplicate Trinity Validator signature")]
    DuplicateSignature,
    #[error("insufficient Trinity Validator signatures: have {have}, need {need}")]
    InsufficientSignatures { have: usize, need: usize },
    #[error("invalid Trinity Validator signature")]
    InvalidSignature,
}

impl TrinityValidatorSet {
    /// Create a new Trinity Validator set with exactly 3 validators.
    pub fn new(validators: [PubKey; 3]) -> Self {
        let validator_set: HashSet<PubKey> = validators.iter().copied().collect();
        assert_eq!(
            validator_set.len(),
            3,
            "Trinity Validators must be 3 unique keys"
        );
        Self {
            validators,
            validator_set,
            threshold: 2,
        }
    }

    /// Check if a public key is a Trinity Validator.
    pub fn is_trinity(&self, pk: &PubKey) -> bool {
        self.validator_set.contains(pk)
    }

    /// Get the Trinity Validator public keys.
    pub fn validators(&self) -> &[PubKey; 3] {
        &self.validators
    }

    /// Verify that an attestation has sufficient valid Trinity Validator signatures.
    /// Each signature is verified against the canonical signing bytes of the operation.
    /// Returns Ok(()) if 2-of-3 have signed validly.
    pub fn verify_attestation(&self, attestation: &BridgeAttestation) -> Result<(), BridgeError> {
        let msg = attestation.operation.signing_bytes();
        let mut seen = HashSet::new();
        let mut valid_count = 0;

        for (validator_pk, sig) in &attestation.signatures {
            if !self.is_trinity(validator_pk) {
                return Err(BridgeError::NotTrinityValidator(*validator_pk));
            }
            if !seen.insert(validator_pk) {
                return Err(BridgeError::DuplicateSignature);
            }
            // Verify Ed25519 signature over canonical operation data
            let vk = VerifyingKey::from_bytes(validator_pk)
                .map_err(|_| BridgeError::InvalidSignature)?;
            let dalek_sig = DalekSig::from_bytes(sig);
            vk.verify_strict(&msg, &dalek_sig)
                .map_err(|_| BridgeError::InvalidSignature)?;
            valid_count += 1;
        }

        if valid_count < self.threshold {
            return Err(BridgeError::InsufficientSignatures {
                have: valid_count,
                need: self.threshold,
            });
        }

        Ok(())
    }

    /// Rotate Trinity Validators. Requires a new set of 3 validators.
    /// In production, this would require 2-of-3 signatures from current validators.
    pub fn rotate(&mut self, new_validators: [PubKey; 3]) {
        let new_set: HashSet<PubKey> = new_validators.iter().copied().collect();
        assert_eq!(
            new_set.len(),
            3,
            "new Trinity Validators must be 3 unique keys"
        );
        self.validators = new_validators;
        self.validator_set = new_set;
    }
}

impl BridgeAttestation {
    pub fn new(operation: BridgeOp) -> Self {
        Self {
            operation,
            signatures: Vec::new(),
        }
    }

    /// Add a guardian's signature to this attestation.
    pub fn add_signature(
        &mut self,
        guardian: PubKey,
        signature: [u8; 64],
    ) -> Result<(), BridgeError> {
        if self.signatures.iter().any(|(pk, _)| *pk == guardian) {
            return Err(BridgeError::DuplicateSignature);
        }
        self.signatures.push((guardian, signature));
        Ok(())
    }

    /// Number of signatures collected.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Generate 3 real Ed25519 keypairs for testing.
    fn test_trinity_keys() -> ([SigningKey; 3], [PubKey; 3], TrinityValidatorSet) {
        let sk0 = SigningKey::from_bytes(&[1u8; 32]);
        let sk1 = SigningKey::from_bytes(&[2u8; 32]);
        let sk2 = SigningKey::from_bytes(&[3u8; 32]);
        let pk0: PubKey = sk0.verifying_key().to_bytes();
        let pk1: PubKey = sk1.verifying_key().to_bytes();
        let pk2: PubKey = sk2.verifying_key().to_bytes();
        let set = TrinityValidatorSet::new([pk0, pk1, pk2]);
        ([sk0, sk1, sk2], [pk0, pk1, pk2], set)
    }

    /// Sign an operation with a signing key.
    fn sign_op(sk: &SigningKey, op: &BridgeOp) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let msg = op.signing_bytes();
        sk.sign(&msg).to_bytes()
    }

    fn test_mint_op() -> BridgeOp {
        BridgeOp::Mint {
            recipient: [0xAAu8; 32],
            amount: 10_000,
            source_chain: "base".into(),
            source_tx: "0xabc".into(),
        }
    }

    #[test]
    fn trinity_set_creation() {
        let (_, pks, set) = test_trinity_keys();
        assert!(set.is_trinity(&pks[0]));
        assert!(set.is_trinity(&pks[1]));
        assert!(set.is_trinity(&pks[2]));
        assert!(!set.is_trinity(&[0xFFu8; 32]));
        assert_eq!(set.threshold, 2);
    }

    #[test]
    fn attestation_two_of_three() {
        let (sks, pks, set) = test_trinity_keys();
        let op = test_mint_op();

        let mut att = BridgeAttestation::new(op.clone());
        att.add_signature(pks[0], sign_op(&sks[0], &op)).unwrap();
        att.add_signature(pks[1], sign_op(&sks[1], &op)).unwrap();

        assert_eq!(att.signature_count(), 2);
        set.verify_attestation(&att).unwrap();
    }

    #[test]
    fn attestation_one_of_three_insufficient() {
        let (sks, pks, set) = test_trinity_keys();
        let op = test_mint_op();

        let mut att = BridgeAttestation::new(op.clone());
        att.add_signature(pks[0], sign_op(&sks[0], &op)).unwrap();

        let err = set.verify_attestation(&att).unwrap_err();
        assert!(matches!(err, BridgeError::InsufficientSignatures { .. }));
    }

    #[test]
    fn attestation_three_of_three() {
        let (sks, pks, set) = test_trinity_keys();

        let op = BridgeOp::Burn {
            sender: [0xBBu8; 32],
            amount: 5_000,
            dest_chain: "arbitrum".into(),
            dest_address: "0x123".into(),
        };

        let mut att = BridgeAttestation::new(op.clone());
        att.add_signature(pks[0], sign_op(&sks[0], &op)).unwrap();
        att.add_signature(pks[1], sign_op(&sks[1], &op)).unwrap();
        att.add_signature(pks[2], sign_op(&sks[2], &op)).unwrap();

        set.verify_attestation(&att).unwrap();
    }

    #[test]
    fn attestation_duplicate_rejected() {
        let (sks, pks, _) = test_trinity_keys();
        let op = test_mint_op();

        let mut att = BridgeAttestation::new(op.clone());
        att.add_signature(pks[0], sign_op(&sks[0], &op)).unwrap();
        let err = att
            .add_signature(pks[0], sign_op(&sks[0], &op))
            .unwrap_err();
        assert!(matches!(err, BridgeError::DuplicateSignature));
    }

    #[test]
    fn attestation_non_trinity_rejected() {
        let (sks, pks, set) = test_trinity_keys();
        let op = test_mint_op();

        let imposter_sk = SigningKey::from_bytes(&[99u8; 32]);
        let imposter_pk: PubKey = imposter_sk.verifying_key().to_bytes();

        let mut att = BridgeAttestation::new(op.clone());
        att.add_signature(pks[0], sign_op(&sks[0], &op)).unwrap();
        att.add_signature(imposter_pk, sign_op(&imposter_sk, &op))
            .unwrap();

        let err = set.verify_attestation(&att).unwrap_err();
        assert!(matches!(err, BridgeError::NotTrinityValidator(_)));
    }

    #[test]
    fn attestation_invalid_signature_rejected() {
        let (_, pks, set) = test_trinity_keys();
        let op = test_mint_op();

        let mut att = BridgeAttestation::new(op);
        // Use a garbage signature (not a valid Ed25519 sig)
        att.add_signature(pks[0], [0u8; 64]).unwrap();
        att.add_signature(pks[1], [0u8; 64]).unwrap();

        let err = set.verify_attestation(&att).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidSignature));
    }

    #[test]
    fn trinity_rotation() {
        let (_, _, mut set) = test_trinity_keys();
        let new_sk0 = SigningKey::from_bytes(&[11u8; 32]);
        let new_sk1 = SigningKey::from_bytes(&[22u8; 32]);
        let new_sk2 = SigningKey::from_bytes(&[33u8; 32]);
        let new_pk0: PubKey = new_sk0.verifying_key().to_bytes();
        let new_pk1: PubKey = new_sk1.verifying_key().to_bytes();
        let new_pk2: PubKey = new_sk2.verifying_key().to_bytes();

        set.rotate([new_pk0, new_pk1, new_pk2]);

        assert!(set.is_trinity(&new_pk0));
        assert!(set.is_trinity(&new_pk1));
        assert!(set.is_trinity(&new_pk2));
        // Old Trinity Validators no longer valid
        let old_sk = SigningKey::from_bytes(&[1u8; 32]);
        assert!(!set.is_trinity(&old_sk.verifying_key().to_bytes()));
    }
}
