use zero_types::Hash;

/// Compute a BLAKE3 hash of arbitrary data.
pub fn blake3_hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Compute the hash of a transfer's storage bytes.
pub fn transfer_hash(storage_bytes: &[u8]) -> Hash {
    blake3_hash(storage_bytes)
}

/// Compute the hash of an account chain block.
/// block_data = previous_hash ++ transfer_hash ++ new_balance (4 bytes LE)
pub fn chain_block_hash(previous: &Hash, transfer_hash: &Hash, new_balance: u32) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(previous);
    hasher.update(transfer_hash);
    hasher.update(&new_balance.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let h1 = blake3_hash(b"hello zero");
        let h2 = blake3_hash(b"hello zero");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_different_hashes() {
        let h1 = blake3_hash(b"a");
        let h2 = blake3_hash(b"b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn chain_block_hash_deterministic() {
        let prev = [0u8; 32];
        let tx_hash = [1u8; 32];
        let h1 = chain_block_hash(&prev, &tx_hash, 500);
        let h2 = chain_block_hash(&prev, &tx_hash, 500);
        assert_eq!(h1, h2);
    }
}
