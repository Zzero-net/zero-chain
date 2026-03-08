//! Signature coordination between Trinity Validators.
//!
//! When a Trinity Validator sees a deposit or burn event, it signs and
//! shares its signature with the other two validators. Once 2-of-3
//! signatures are collected, the operation is executed.
//!
//! Coordination is done via HTTP between the 3 validators' bridge services.

use std::collections::HashMap;

use crate::eip712::{Eip712Error, recover_signer};

/// Metadata for a pending mint operation (deposit details needed for POST submission).
#[derive(Debug, Clone)]
pub struct MintMeta {
    pub recipient: [u8; 32],
    pub amount: u64,
    pub source_chain: String,
    /// Hex-encoded source transaction hash (no 0x prefix).
    pub source_tx: String,
}

/// A pending bridge operation waiting for signatures.
#[derive(Debug, Clone)]
pub struct PendingOperation {
    /// Unique operation ID (bridge_id for releases, source_tx for mints)
    pub op_id: [u8; 32],
    /// Type of operation
    pub op_type: OpType,
    /// Collected ECDSA signatures: signer_address → 65-byte signature
    pub ecdsa_signatures: HashMap<[u8; 20], [u8; 65]>,
    /// Collected Ed25519 signatures: signer_pubkey → 64-byte signature
    pub ed25519_signatures: HashMap<[u8; 32], [u8; 64]>,
    /// The EIP-712 digest (for release operations)
    pub digest: Option<[u8; 32]>,
    /// Mint operation metadata (for mint operations)
    pub mint_meta: Option<MintMeta>,
    /// Creation timestamp
    pub created_at: u64,
}

/// Type of bridge operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpType {
    /// Bridge-in: deposit detected, need to mint Z
    Mint,
    /// Bridge-out: burn detected, need to release stablecoins
    Release,
}

/// Collects and manages signatures from Trinity Validators.
pub struct SignatureCollector {
    /// Known Trinity Validator Ethereum addresses
    guardians: [[u8; 20]; 3],
    /// Known Trinity Validator Ed25519 public keys
    trinity_pubkeys: [[u8; 32]; 3],
    /// Pending operations awaiting signatures
    pending: HashMap<[u8; 32], PendingOperation>,
    /// Required signature count
    threshold: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("unknown guardian address")]
    UnknownGuardian,
    #[error("unknown Trinity Validator pubkey")]
    UnknownTrinityValidator,
    #[error("duplicate signature from same signer")]
    DuplicateSignature,
    #[error("operation not found: {0}")]
    OperationNotFound(String),
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(#[from] Eip712Error),
}

/// Result of adding a signature — either still pending or threshold met.
#[derive(Debug)]
pub enum SignatureResult {
    /// Need more signatures
    Pending { have: usize, need: usize },
    /// Threshold met, operation ready to execute
    ThresholdMet {
        op_id: [u8; 32],
        /// Concatenated ECDSA signatures sorted by signer address (for vault release)
        ecdsa_sigs_sorted: Vec<u8>,
    },
}

impl SignatureCollector {
    pub fn new(guardians: [[u8; 20]; 3], trinity_pubkeys: [[u8; 32]; 3]) -> Self {
        Self {
            guardians,
            trinity_pubkeys,
            pending: HashMap::new(),
            threshold: 2,
        }
    }

    /// Start tracking a new operation.
    pub fn create_operation(
        &mut self,
        op_id: [u8; 32],
        op_type: OpType,
        digest: Option<[u8; 32]>,
        now: u64,
    ) {
        self.pending.entry(op_id).or_insert(PendingOperation {
            op_id,
            op_type,
            ecdsa_signatures: HashMap::new(),
            ed25519_signatures: HashMap::new(),
            digest,
            mint_meta: None,
            created_at: now,
        });
    }

    /// Add an ECDSA signature for a release operation.
    /// Verifies the signature recovers to a known guardian address.
    pub fn add_ecdsa_signature(
        &mut self,
        op_id: &[u8; 32],
        signature: &[u8; 65],
    ) -> Result<SignatureResult, CoordinatorError> {
        let op = self
            .pending
            .get_mut(op_id)
            .ok_or_else(|| CoordinatorError::OperationNotFound(hex::encode(op_id)))?;

        let digest = op
            .digest
            .ok_or_else(|| CoordinatorError::OperationNotFound("no digest set".into()))?;

        // Recover signer from signature
        let signer = recover_signer(&digest, signature)?;

        // Verify signer is a known guardian
        if !self.guardians.contains(&signer) {
            return Err(CoordinatorError::UnknownGuardian);
        }

        // Check for duplicate
        if op.ecdsa_signatures.contains_key(&signer) {
            return Err(CoordinatorError::DuplicateSignature);
        }

        op.ecdsa_signatures.insert(signer, *signature);

        let have = op.ecdsa_signatures.len();
        if have >= self.threshold {
            Ok(SignatureResult::ThresholdMet {
                op_id: *op_id,
                ecdsa_sigs_sorted: self.build_sorted_ecdsa_sigs(op_id),
            })
        } else {
            Ok(SignatureResult::Pending {
                have,
                need: self.threshold,
            })
        }
    }

    /// Add an Ed25519 signature for a mint attestation.
    pub fn add_ed25519_signature(
        &mut self,
        op_id: &[u8; 32],
        pubkey: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<SignatureResult, CoordinatorError> {
        let op = self
            .pending
            .get_mut(op_id)
            .ok_or_else(|| CoordinatorError::OperationNotFound(hex::encode(op_id)))?;

        // Verify pubkey is a known Trinity Validator
        if !self.trinity_pubkeys.contains(pubkey) {
            return Err(CoordinatorError::UnknownTrinityValidator);
        }

        if op.ed25519_signatures.contains_key(pubkey) {
            return Err(CoordinatorError::DuplicateSignature);
        }

        op.ed25519_signatures.insert(*pubkey, *signature);

        let have = op.ed25519_signatures.len();
        if have >= self.threshold {
            Ok(SignatureResult::ThresholdMet {
                op_id: *op_id,
                ecdsa_sigs_sorted: Vec::new(), // Not applicable for mints
            })
        } else {
            Ok(SignatureResult::Pending {
                have,
                need: self.threshold,
            })
        }
    }

    /// Build concatenated ECDSA signatures sorted by signer address ascending.
    /// This matches the vault contract's requirement for sorted signatures.
    fn build_sorted_ecdsa_sigs(&self, op_id: &[u8; 32]) -> Vec<u8> {
        let op = match self.pending.get(op_id) {
            Some(op) => op,
            None => return Vec::new(),
        };

        let mut entries: Vec<([u8; 20], [u8; 65])> = op
            .ecdsa_signatures
            .iter()
            .map(|(addr, sig)| (*addr, *sig))
            .collect();

        // Sort by address ascending (matching Solidity's signer > lastSigner check)
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut result = Vec::with_capacity(entries.len() * 65);
        for (_, sig) in &entries {
            result.extend_from_slice(sig);
        }
        result
    }

    /// Store mint metadata for a pending operation.
    pub fn set_mint_meta(&mut self, op_id: &[u8; 32], meta: MintMeta) {
        if let Some(op) = self.pending.get_mut(op_id) {
            op.mint_meta = Some(meta);
        }
    }

    /// Get a reference to a pending operation by ID.
    pub fn get_operation(&self, op_id: &[u8; 32]) -> Option<&PendingOperation> {
        self.pending.get(op_id)
    }

    /// Check if an operation has reached threshold.
    pub fn is_complete(&self, op_id: &[u8; 32], op_type: &OpType) -> bool {
        match self.pending.get(op_id) {
            Some(op) => match op_type {
                OpType::Release => op.ecdsa_signatures.len() >= self.threshold,
                OpType::Mint => op.ed25519_signatures.len() >= self.threshold,
            },
            None => false,
        }
    }

    /// Remove a completed operation.
    pub fn remove_operation(&mut self, op_id: &[u8; 32]) -> Option<PendingOperation> {
        self.pending.remove(op_id)
    }

    /// Get the pending operation count.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Clean up stale operations older than max_age_secs.
    pub fn cleanup_stale(&mut self, now: u64, max_age_secs: u64) {
        self.pending
            .retain(|_, op| now - op.created_at < max_age_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eip712::{Eip712Signer, ReleaseParams};

    fn test_keys() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut k1 = [0u8; 32];
        k1[31] = 1;
        let mut k2 = [0u8; 32];
        k2[31] = 2;
        let mut k3 = [0u8; 32];
        k3[31] = 3;
        (k1, k2, k3)
    }

    fn test_collector() -> (SignatureCollector, Eip712Signer, Eip712Signer, Eip712Signer) {
        let (k1, k2, k3) = test_keys();
        let vault = [0xAA; 20];
        let chain_id = 84532;

        let s1 = Eip712Signer::new(&k1, chain_id, vault).unwrap();
        let s2 = Eip712Signer::new(&k2, chain_id, vault).unwrap();
        let s3 = Eip712Signer::new(&k3, chain_id, vault).unwrap();

        let guardians = [s1.address, s2.address, s3.address];
        let trinity_pks = [[0x01; 32], [0x02; 32], [0x03; 32]]; // Ed25519 keys (separate)

        let collector = SignatureCollector::new(guardians, trinity_pks);
        (collector, s1, s2, s3)
    }

    fn test_release_params() -> ReleaseParams {
        ReleaseParams {
            token: [0x11; 20],
            amount: 1_000_000,
            recipient: [0x22; 20],
            bridge_id: [0x33; 32],
            dest_chain: "base".into(),
        }
    }

    #[test]
    fn collect_two_of_three_ecdsa() {
        let (mut collector, s1, s2, _s3) = test_collector();
        let params = test_release_params();
        let op_id = params.bridge_id;

        let signed1 = s1.sign_release(&params).unwrap();
        let signed2 = s2.sign_release(&params).unwrap();

        collector.create_operation(op_id, OpType::Release, Some(signed1.digest), 1000);

        // First signature → pending
        let result = collector
            .add_ecdsa_signature(&op_id, &signed1.signature)
            .unwrap();
        assert!(matches!(
            result,
            SignatureResult::Pending { have: 1, need: 2 }
        ));

        // Second signature → threshold met
        let result = collector
            .add_ecdsa_signature(&op_id, &signed2.signature)
            .unwrap();
        match result {
            SignatureResult::ThresholdMet {
                ecdsa_sigs_sorted, ..
            } => {
                // Should be 130 bytes (2 × 65)
                assert_eq!(ecdsa_sigs_sorted.len(), 130);
            }
            _ => panic!("expected ThresholdMet"),
        }
    }

    #[test]
    fn signatures_sorted_by_address() {
        let (mut collector, s1, s2, s3) = test_collector();
        let params = test_release_params();
        let op_id = params.bridge_id;
        let signed1 = s1.sign_release(&params).unwrap();
        let signed2 = s2.sign_release(&params).unwrap();
        let signed3 = s3.sign_release(&params).unwrap();

        collector.create_operation(op_id, OpType::Release, Some(signed1.digest), 1000);

        // Add in reverse order (3, 1, 2) — output should still be sorted by address
        collector
            .add_ecdsa_signature(&op_id, &signed3.signature)
            .unwrap();
        collector
            .add_ecdsa_signature(&op_id, &signed1.signature)
            .unwrap();
        let result = collector
            .add_ecdsa_signature(&op_id, &signed2.signature)
            .unwrap();

        match result {
            SignatureResult::ThresholdMet {
                ecdsa_sigs_sorted, ..
            } => {
                // 3 × 65 = 195 bytes
                assert_eq!(ecdsa_sigs_sorted.len(), 195);

                // Recover each signer and verify ascending order
                let mut prev = [0u8; 20];
                for i in 0..3 {
                    let sig: [u8; 65] = ecdsa_sigs_sorted[i * 65..(i + 1) * 65].try_into().unwrap();
                    let addr = recover_signer(&signed1.digest, &sig).unwrap();
                    assert!(addr > prev, "signatures not sorted at index {}", i);
                    prev = addr;
                }
            }
            _ => panic!("expected ThresholdMet"),
        }
    }

    #[test]
    fn duplicate_signer_rejected() {
        let (mut collector, s1, _, _) = test_collector();
        let params = test_release_params();
        let op_id = params.bridge_id;
        let signed = s1.sign_release(&params).unwrap();

        collector.create_operation(op_id, OpType::Release, Some(signed.digest), 1000);
        collector
            .add_ecdsa_signature(&op_id, &signed.signature)
            .unwrap();

        // Same signature again
        let err = collector
            .add_ecdsa_signature(&op_id, &signed.signature)
            .unwrap_err();
        assert!(matches!(err, CoordinatorError::DuplicateSignature));
    }

    #[test]
    fn unknown_signer_rejected() {
        let (mut collector, _, _, _) = test_collector();
        let params = test_release_params();
        let op_id = params.bridge_id;

        // Create a signer that's not a guardian
        let mut rogue_key = [0u8; 32];
        rogue_key[31] = 99;
        let rogue = Eip712Signer::new(&rogue_key, 84532, [0xAA; 20]).unwrap();
        let signed = rogue.sign_release(&params).unwrap();

        collector.create_operation(op_id, OpType::Release, Some(signed.digest), 1000);
        let err = collector
            .add_ecdsa_signature(&op_id, &signed.signature)
            .unwrap_err();
        assert!(matches!(err, CoordinatorError::UnknownGuardian));
    }

    #[test]
    fn operation_not_found() {
        let (mut collector, s1, _, _) = test_collector();
        let params = test_release_params();
        let signed = s1.sign_release(&params).unwrap();

        let fake_id = [0xFF; 32];
        let err = collector
            .add_ecdsa_signature(&fake_id, &signed.signature)
            .unwrap_err();
        assert!(matches!(err, CoordinatorError::OperationNotFound(_)));
    }

    #[test]
    fn ed25519_mint_collection() {
        let (mut collector, _, _, _) = test_collector();
        let op_id = [0x44; 32];

        collector.create_operation(op_id, OpType::Mint, None, 1000);

        let pk1 = [0x01; 32];
        let pk2 = [0x02; 32];
        let sig1 = [0xAA; 64];
        let sig2 = [0xBB; 64];

        let result = collector
            .add_ed25519_signature(&op_id, &pk1, &sig1)
            .unwrap();
        assert!(matches!(
            result,
            SignatureResult::Pending { have: 1, need: 2 }
        ));

        let result = collector
            .add_ed25519_signature(&op_id, &pk2, &sig2)
            .unwrap();
        assert!(matches!(result, SignatureResult::ThresholdMet { .. }));
    }

    #[test]
    fn cleanup_stale_operations() {
        let (mut collector, _, _, _) = test_collector();

        collector.create_operation([0x01; 32], OpType::Mint, None, 1000);
        collector.create_operation([0x02; 32], OpType::Mint, None, 5000);
        assert_eq!(collector.pending_count(), 2);

        // Clean up operations older than 3000 seconds at time 6000
        collector.cleanup_stale(6000, 3000);

        // Only the second operation should remain (created at 5000, age = 1000 < 3000)
        assert_eq!(collector.pending_count(), 1);
    }

    #[test]
    fn is_complete_check() {
        let (mut collector, s1, s2, _) = test_collector();
        let params = test_release_params();
        let op_id = params.bridge_id;
        let signed1 = s1.sign_release(&params).unwrap();
        let signed2 = s2.sign_release(&params).unwrap();

        collector.create_operation(op_id, OpType::Release, Some(signed1.digest), 1000);

        assert!(!collector.is_complete(&op_id, &OpType::Release));

        collector
            .add_ecdsa_signature(&op_id, &signed1.signature)
            .unwrap();
        assert!(!collector.is_complete(&op_id, &OpType::Release));

        collector
            .add_ecdsa_signature(&op_id, &signed2.signature)
            .unwrap();
        assert!(collector.is_complete(&op_id, &OpType::Release));
    }

    #[test]
    fn remove_operation() {
        let (mut collector, _, _, _) = test_collector();
        let op_id = [0x55; 32];
        collector.create_operation(op_id, OpType::Mint, None, 1000);
        assert_eq!(collector.pending_count(), 1);

        let removed = collector.remove_operation(&op_id);
        assert!(removed.is_some());
        assert_eq!(collector.pending_count(), 0);
    }
}
