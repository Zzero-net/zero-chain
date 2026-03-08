use serde::{Deserialize, Serialize};

use crate::{Amount, Hash, Nonce};

/// Account state: 48 bytes.
///
/// Layout:
///   balance: [4]   u32, current balance in units
///   nonce:   [4]   u32, last used nonce
///   head:    [32]  BLAKE3 hash of latest block in account chain
///   flags:   [8]   reserved (frozen, validator, etc.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub balance: Amount,
    pub nonce: Nonce,
    pub head: Hash,
    pub flags: u64,
}

/// Account flags.
pub mod flags {
    /// Account is frozen (cannot send, can still receive).
    pub const FROZEN: u64 = 1 << 0;
    /// Account is a registered validator.
    pub const VALIDATOR: u64 = 1 << 1;
}

pub const ACCOUNT_SIZE: usize = 48;

impl Account {
    /// A new empty account (zero balance, zero nonce, no history).
    pub const fn empty() -> Self {
        Self {
            balance: 0,
            nonce: 0,
            head: [0u8; 32],
            flags: 0,
        }
    }

    pub fn is_frozen(&self) -> bool {
        self.flags & flags::FROZEN != 0
    }

    pub fn is_validator(&self) -> bool {
        self.flags & flags::VALIDATOR != 0
    }

    /// Serialize to 48 bytes.
    pub fn to_bytes(&self) -> [u8; ACCOUNT_SIZE] {
        let mut buf = [0u8; ACCOUNT_SIZE];
        buf[0..4].copy_from_slice(&self.balance.to_le_bytes());
        buf[4..8].copy_from_slice(&self.nonce.to_le_bytes());
        buf[8..40].copy_from_slice(&self.head);
        buf[40..48].copy_from_slice(&self.flags.to_le_bytes());
        buf
    }

    /// Deserialize from 48 bytes.
    pub fn from_bytes(buf: &[u8; ACCOUNT_SIZE]) -> Self {
        Self {
            balance: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            nonce: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            head: buf[8..40].try_into().unwrap(),
            flags: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_account() {
        let a = Account::empty();
        assert_eq!(a.balance, 0);
        assert_eq!(a.nonce, 0);
        assert_eq!(a.head, [0u8; 32]);
        assert_eq!(a.flags, 0);
        assert!(!a.is_frozen());
        assert!(!a.is_validator());
    }

    #[test]
    fn roundtrip() {
        let a = Account {
            balance: 12345,
            nonce: 99,
            head: [0xFF; 32],
            flags: flags::FROZEN | flags::VALIDATOR,
        };
        let bytes = a.to_bytes();
        assert_eq!(bytes.len(), 48);
        let decoded = Account::from_bytes(&bytes);
        assert_eq!(a, decoded);
        assert!(decoded.is_frozen());
        assert!(decoded.is_validator());
    }
}
