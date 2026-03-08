use zero_types::{transfer::STORAGE_SIZE, Hash, Transfer};

/// Fixed-size ring buffer for the recent transfer log.
///
/// Stores transfers in a pre-allocated contiguous buffer.
/// When full, the oldest entries are overwritten — no compaction,
/// no GC pauses, O(1) append + O(1) evict.
///
/// Inspired by TigerBeetle's append-only log and Sonic/Carmen's
/// LiveDB-only approach for validators.
pub struct TransferLog {
    /// Pre-allocated buffer: capacity * STORAGE_SIZE bytes.
    data: Vec<u8>,
    /// Maximum number of transfers the buffer can hold.
    capacity: usize,
    /// Index of the next write position (wraps around).
    write_pos: usize,
    /// Total number of transfers written (never wraps — monotonic counter).
    total_written: u64,
    /// BLAKE3 hashes for each slot (for lookup by hash).
    hashes: Vec<Hash>,
}

impl TransferLog {
    /// Create a new transfer log with the given capacity (number of transfers).
    ///
    /// Memory usage: capacity * (STORAGE_SIZE + 32) bytes.
    /// Example: 1M transfers = 1M * (136 + 32) = ~168 MB
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "capacity must be > 0");
        Self {
            data: vec![0u8; capacity * STORAGE_SIZE],
            capacity,
            write_pos: 0,
            total_written: 0,
            hashes: vec![[0u8; 32]; capacity],
        }
    }

    /// Append a transfer to the log. Returns the global sequence number.
    pub fn append(&mut self, transfer: &Transfer, hash: Hash) -> u64 {
        let offset = self.write_pos * STORAGE_SIZE;
        let bytes = transfer.to_storage_bytes();
        self.data[offset..offset + STORAGE_SIZE].copy_from_slice(&bytes);
        self.hashes[self.write_pos] = hash;

        let seq = self.total_written;
        self.write_pos = (self.write_pos + 1) % self.capacity;
        self.total_written += 1;
        seq
    }

    /// Read a transfer by its global sequence number.
    /// Returns None if the transfer has been evicted (overwritten).
    pub fn get_by_seq(&self, seq: u64) -> Option<Transfer> {
        if self.total_written == 0 {
            return None;
        }
        // Check if the sequence is still in the buffer
        let oldest_seq = self.oldest_seq();
        if seq < oldest_seq || seq >= self.total_written {
            return None;
        }
        let slot = (seq % self.capacity as u64) as usize;
        let offset = slot * STORAGE_SIZE;
        let buf: &[u8; STORAGE_SIZE] = self.data[offset..offset + STORAGE_SIZE]
            .try_into()
            .unwrap();
        Some(Transfer::from_storage_bytes(buf))
    }

    /// Get the hash at a given sequence number.
    pub fn get_hash(&self, seq: u64) -> Option<Hash> {
        let oldest_seq = self.oldest_seq();
        if seq < oldest_seq || seq >= self.total_written {
            return None;
        }
        let slot = (seq % self.capacity as u64) as usize;
        Some(self.hashes[slot])
    }

    /// Find a transfer by hash (linear scan — use sparingly).
    pub fn find_by_hash(&self, hash: &Hash) -> Option<(u64, Transfer)> {
        let oldest = self.oldest_seq();
        let count = self.len();
        for i in 0..count {
            let slot = ((oldest + i as u64) % self.capacity as u64) as usize;
            if &self.hashes[slot] == hash {
                let offset = slot * STORAGE_SIZE;
                let buf: &[u8; STORAGE_SIZE] = self.data[offset..offset + STORAGE_SIZE]
                    .try_into()
                    .unwrap();
                return Some((oldest + i as u64, Transfer::from_storage_bytes(buf)));
            }
        }
        None
    }

    /// The sequence number of the oldest transfer still in the buffer.
    pub fn oldest_seq(&self) -> u64 {
        if self.total_written <= self.capacity as u64 {
            0
        } else {
            self.total_written - self.capacity as u64
        }
    }

    /// Number of transfers currently in the buffer.
    pub fn len(&self) -> usize {
        std::cmp::min(self.total_written as usize, self.capacity)
    }

    pub fn is_empty(&self) -> bool {
        self.total_written == 0
    }

    /// Total transfers ever written.
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Buffer capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the N most recent transfers (newest first).
    pub fn recent(&self, n: usize) -> Vec<Transfer> {
        self.recent_with_seq(n).into_iter().map(|(_, tx)| tx).collect()
    }

    /// Get the N most recent transfers with their sequence numbers (newest first).
    pub fn recent_with_seq(&self, n: usize) -> Vec<(u64, Transfer)> {
        let count = std::cmp::min(n, self.len());
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let seq = self.total_written - 1 - i as u64;
            if let Some(tx) = self.get_by_seq(seq) {
                result.push((seq, tx));
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_transfer(from_byte: u8, nonce: u32) -> Transfer {
        Transfer {
            from: [from_byte; 32],
            to: [0xFF; 32],
            amount: 10,
            nonce,
            signature: [0xAA; 64],
        }
    }

    #[test]
    fn append_and_retrieve() {
        let mut log = TransferLog::new(10);
        let tx = make_transfer(1, 1);
        let hash = [0xBB; 32];
        let seq = log.append(&tx, hash);
        assert_eq!(seq, 0);
        assert_eq!(log.len(), 1);

        let retrieved = log.get_by_seq(0).unwrap();
        assert_eq!(retrieved, tx);
        assert_eq!(log.get_hash(0).unwrap(), hash);
    }

    #[test]
    fn ring_buffer_eviction() {
        let mut log = TransferLog::new(3);

        for i in 0..5u32 {
            let tx = make_transfer(i as u8, i);
            log.append(&tx, [i as u8; 32]);
        }

        assert_eq!(log.len(), 3);
        assert_eq!(log.total_written(), 5);
        assert_eq!(log.oldest_seq(), 2);

        // Seq 0 and 1 should be evicted
        assert!(log.get_by_seq(0).is_none());
        assert!(log.get_by_seq(1).is_none());

        // Seq 2, 3, 4 should be present
        assert!(log.get_by_seq(2).is_some());
        assert!(log.get_by_seq(3).is_some());
        assert!(log.get_by_seq(4).is_some());
    }

    #[test]
    fn find_by_hash() {
        let mut log = TransferLog::new(10);
        let tx = make_transfer(7, 42);
        let hash = [0xCC; 32];
        log.append(&tx, hash);

        let (seq, found) = log.find_by_hash(&hash).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(found, tx);

        assert!(log.find_by_hash(&[0xDD; 32]).is_none());
    }

    #[test]
    fn recent_returns_newest_first() {
        let mut log = TransferLog::new(10);
        for i in 0..5u32 {
            log.append(&make_transfer(i as u8, i), [i as u8; 32]);
        }

        let recent = log.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].nonce, 4); // newest
        assert_eq!(recent[1].nonce, 3);
        assert_eq!(recent[2].nonce, 2);
    }
}
