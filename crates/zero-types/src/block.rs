use serde::{Deserialize, Serialize};

use crate::{Hash, Round, TimestampMs, ValidatorIndex};

/// 32-byte BLAKE3 block hash.
pub type BlockHash = Hash;

/// Reference to a block in the consensus DAG.
///
/// Inspired by Mysticeti's BlockRef: round + author + digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockRef {
    pub round: Round,
    pub author: ValidatorIndex,
    pub digest: BlockHash,
}

impl BlockRef {
    pub fn new(round: Round, author: ValidatorIndex, digest: BlockHash) -> Self {
        Self {
            round,
            author,
            digest,
        }
    }
}

impl std::fmt::Display for BlockRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "B{}({},{})",
            self.round,
            self.author,
            hex::encode(&self.digest[..4])
        )
    }
}

/// A consensus event (block) in the DAG.
///
/// Each validator produces events containing batches of transfers.
/// Events reference parent events to form a DAG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    /// The round this event belongs to.
    pub round: Round,
    /// The validator that created this event.
    pub author: ValidatorIndex,
    /// Timestamp assigned by the creating validator.
    pub timestamp: TimestampMs,
    /// References to parent events (self-parent + other-parents).
    pub parents: Vec<BlockRef>,
    /// Batch of transfer indices or raw transfers included in this event.
    /// In the finalized path, these are offsets into the transfer pool.
    pub transactions: Vec<u32>,
    /// BLAKE3 hash of this event (computed over all fields above).
    pub digest: BlockHash,
}

impl Event {
    pub fn reference(&self) -> BlockRef {
        BlockRef {
            round: self.round,
            author: self.author,
            digest: self.digest,
        }
    }
}
