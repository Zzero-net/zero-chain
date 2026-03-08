use serde::{Deserialize, Serialize};

use crate::{Amount, Hash, Nonce, PubKey};

pub use crate::params::{MAX_TRANSFER_AMOUNT, TRANSFER_FEE};

/// Size of a transfer on the wire (without full signature).
pub const WIRE_SIZE: usize = 100;

/// Size of a transfer in storage (with full signature).
pub const STORAGE_SIZE: usize = 136;

/// A single Zero transfer.
///
/// Wire format (100 bytes):
///   from:      [32]  Ed25519 public key
///   to:        [32]  Ed25519 public key
///   amount:    [4]   u32 LE
///   nonce:     [4]   u32 LE
///   signature: [28]  truncated Ed25519
///
/// Internal/storage format (136 bytes):
///   from:      [32]
///   to:        [32]
///   amount:    [4]
///   nonce:     [4]
///   signature: [64]  full Ed25519
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    pub from: PubKey,
    pub to: PubKey,
    pub amount: Amount,
    pub nonce: Nonce,
    /// 64-byte Ed25519 signature. Stored as Vec for serde compatibility.
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(bytes.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Deserialize::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes for signature"))
    }
}

impl Transfer {
    /// The bytes that are signed: from ++ to ++ amount ++ nonce (72 bytes).
    pub fn signing_bytes(&self) -> [u8; 72] {
        let mut buf = [0u8; 72];
        buf[0..32].copy_from_slice(&self.from);
        buf[32..64].copy_from_slice(&self.to);
        buf[64..68].copy_from_slice(&self.amount.to_le_bytes());
        buf[68..72].copy_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    /// Encode to internal storage format (136 bytes).
    pub fn to_storage_bytes(&self) -> [u8; STORAGE_SIZE] {
        let mut buf = [0u8; STORAGE_SIZE];
        buf[0..32].copy_from_slice(&self.from);
        buf[32..64].copy_from_slice(&self.to);
        buf[64..68].copy_from_slice(&self.amount.to_le_bytes());
        buf[68..72].copy_from_slice(&self.nonce.to_le_bytes());
        buf[72..136].copy_from_slice(&self.signature);
        buf
    }

    /// Decode from internal storage format (136 bytes).
    pub fn from_storage_bytes(buf: &[u8; STORAGE_SIZE]) -> Self {
        let mut from = [0u8; 32];
        let mut to = [0u8; 32];
        let mut sig = [0u8; 64];
        from.copy_from_slice(&buf[0..32]);
        to.copy_from_slice(&buf[32..64]);
        let amount = u32::from_le_bytes(buf[64..68].try_into().unwrap());
        let nonce = u32::from_le_bytes(buf[68..72].try_into().unwrap());
        sig.copy_from_slice(&buf[72..136]);
        Self {
            from,
            to,
            amount,
            nonce,
            signature: sig,
        }
    }

    /// Encode to wire format (100 bytes, truncated signature).
    pub fn to_wire_bytes(&self) -> [u8; WIRE_SIZE] {
        let mut buf = [0u8; WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.from);
        buf[32..64].copy_from_slice(&self.to);
        buf[64..68].copy_from_slice(&self.amount.to_le_bytes());
        buf[68..72].copy_from_slice(&self.nonce.to_le_bytes());
        buf[72..100].copy_from_slice(&self.signature[..28]);
        buf
    }

    /// Compute the BLAKE3 hash of this transfer (over signing bytes + full signature).
    pub fn hash_with(&self, hasher: impl Fn(&[u8]) -> Hash) -> Hash {
        hasher(&self.to_storage_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_roundtrip() {
        let tx = Transfer {
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 100,
            nonce: 42,
            signature: [0xAB; 64],
        };
        let bytes = tx.to_storage_bytes();
        let decoded = Transfer::from_storage_bytes(&bytes);
        assert_eq!(tx, decoded);
    }

    #[test]
    fn wire_format_is_100_bytes() {
        let tx = Transfer {
            from: [0u8; 32],
            to: [0u8; 32],
            amount: 0,
            nonce: 0,
            signature: [0u8; 64],
        };
        assert_eq!(tx.to_wire_bytes().len(), 100);
    }

    #[test]
    fn signing_bytes_are_72() {
        let tx = Transfer {
            from: [0u8; 32],
            to: [0u8; 32],
            amount: 0,
            nonce: 0,
            signature: [0u8; 64],
        };
        assert_eq!(tx.signing_bytes().len(), 72);
    }
}
