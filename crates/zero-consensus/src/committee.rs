use std::collections::HashMap;

use zero_types::{PubKey, ValidatorIndex};

/// A validator's identity and stake.
#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    pub index: ValidatorIndex,
    pub public_key: PubKey,
    pub stake: u64,
}

/// The current validator committee.
///
/// Maps validator indices to their identity/stake.
/// Stake is used for weighted quorum calculations.
pub struct Committee {
    validators: Vec<ValidatorInfo>,
    index_by_key: HashMap<PubKey, ValidatorIndex>,
    total_stake: u64,
}

impl Committee {
    pub fn new(validators: Vec<ValidatorInfo>) -> Self {
        let total_stake = validators.iter().map(|v| v.stake).sum();
        let index_by_key = validators
            .iter()
            .map(|v| (v.public_key, v.index))
            .collect();
        Self {
            validators,
            index_by_key,
            total_stake,
        }
    }

    /// Number of validators.
    pub fn size(&self) -> usize {
        self.validators.len()
    }

    /// Total stake across all validators.
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// Stake required for a 2/3+ quorum.
    pub fn quorum_threshold(&self) -> u64 {
        self.total_stake * 2 / 3 + 1
    }

    /// Maximum byzantine stake tolerated (< 1/3).
    pub fn max_faulty_stake(&self) -> u64 {
        (self.total_stake - 1) / 3
    }

    /// Look up a validator by public key.
    pub fn index_of(&self, key: &PubKey) -> Option<ValidatorIndex> {
        self.index_by_key.get(key).copied()
    }

    /// Get validator info by index.
    pub fn validator(&self, index: ValidatorIndex) -> Option<&ValidatorInfo> {
        self.validators.get(index as usize)
    }

    /// Iterate over all validators.
    pub fn validators(&self) -> &[ValidatorInfo] {
        &self.validators
    }

    /// Check if a set of validator stakes reaches quorum.
    pub fn has_quorum(&self, stakes: impl Iterator<Item = u64>) -> bool {
        let total: u64 = stakes.sum();
        total >= self.quorum_threshold()
    }

    /// Calculate a validator's share of the fee pool.
    pub fn fee_share(&self, index: ValidatorIndex, total_fees: u64) -> u64 {
        if let Some(v) = self.validator(index) {
            if self.total_stake == 0 {
                return 0;
            }
            total_fees * v.stake / self.total_stake
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_committee() -> Committee {
        Committee::new(vec![
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
            ValidatorInfo {
                index: 3,
                public_key: [4u8; 32],
                stake: 100,
            },
        ])
    }

    #[test]
    fn quorum_threshold() {
        let c = test_committee();
        assert_eq!(c.total_stake(), 400);
        assert_eq!(c.quorum_threshold(), 267); // 400 * 2/3 + 1
    }

    #[test]
    fn fee_share_equal_stake() {
        let c = test_committee();
        // 1000 fees, 4 validators with equal stake: 250 each
        assert_eq!(c.fee_share(0, 1000), 250);
        assert_eq!(c.fee_share(1, 1000), 250);
    }

    #[test]
    fn index_lookup() {
        let c = test_committee();
        assert_eq!(c.index_of(&[1u8; 32]), Some(0));
        assert_eq!(c.index_of(&[5u8; 32]), None);
    }
}
