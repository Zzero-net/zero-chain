use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use tracing::info;
use zero_types::{Account, PubKey};

use crate::AccountStore;

/// Snapshot format version. Increment when format changes.
const SNAPSHOT_VERSION: u32 = 1;

/// Header: version(4) + account_count(8) + total_written(8) = 20 bytes.
const HEADER_SIZE: usize = 20;

/// Per-account record: pubkey(32) + account(48) = 80 bytes.
const RECORD_SIZE: usize = 80;

/// Save account state to a binary snapshot file.
///
/// Format:
///   [4 bytes]  version (u32 LE)
///   [8 bytes]  account count (u64 LE)
///   [8 bytes]  total_written from transfer log (u64 LE, for resume)
///   For each account:
///     [32 bytes] public key
///     [48 bytes] account state (Account::to_bytes())
pub fn save_snapshot(
    store: &AccountStore,
    total_written: u64,
    path: &Path,
) -> io::Result<()> {
    let tmp_path = path.with_extension("tmp");

    let mut file = fs::File::create(&tmp_path)?;

    // Collect all accounts (DashMap iteration)
    let accounts: Vec<(PubKey, Account)> = store.iter_accounts();
    let count = accounts.len() as u64;

    // Write header
    file.write_all(&SNAPSHOT_VERSION.to_le_bytes())?;
    file.write_all(&count.to_le_bytes())?;
    file.write_all(&total_written.to_le_bytes())?;

    // Write each account
    for (pk, acct) in &accounts {
        file.write_all(pk)?;
        file.write_all(&acct.to_bytes())?;
    }

    file.sync_all()?;
    drop(file);

    // Atomic rename
    fs::rename(&tmp_path, path)?;

    info!(
        accounts = count,
        total_written,
        path = %path.display(),
        "Snapshot saved"
    );

    Ok(())
}

/// Load account state from a snapshot file.
/// Returns (AccountStore, total_written).
pub fn load_snapshot(path: &Path) -> Result<(AccountStore, u64), String> {
    let data = fs::read(path)
        .map_err(|e| format!("Failed to read snapshot {}: {}", path.display(), e))?;

    if data.len() < HEADER_SIZE {
        return Err("Snapshot file too small for header".into());
    }

    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if version != SNAPSHOT_VERSION {
        return Err(format!(
            "Unsupported snapshot version: {} (expected {})",
            version, SNAPSHOT_VERSION
        ));
    }

    let count = u64::from_le_bytes(data[4..12].try_into().unwrap()) as usize;
    let total_written = u64::from_le_bytes(data[12..20].try_into().unwrap());

    let expected_size = HEADER_SIZE + count * RECORD_SIZE;
    if data.len() < expected_size {
        return Err(format!(
            "Snapshot truncated: expected {} bytes, got {}",
            expected_size,
            data.len()
        ));
    }

    let store = AccountStore::with_capacity(count);
    let mut offset = HEADER_SIZE;

    for _ in 0..count {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let acct_bytes: [u8; 48] = data[offset..offset + 48].try_into().unwrap();
        let acct = Account::from_bytes(&acct_bytes);
        offset += 48;

        store.set(pk, acct);
    }

    info!(
        accounts = count,
        total_written,
        path = %path.display(),
        "Snapshot loaded"
    );

    Ok((store, total_written))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip() {
        let store = AccountStore::new();
        store.mint(&[1u8; 32], 1000);
        store.mint(&[2u8; 32], 2000);
        store.mint(&[3u8; 32], 500);

        let dir = std::env::temp_dir();
        let path = dir.join("zero-test-snapshot.bin");

        save_snapshot(&store, 42, &path).unwrap();

        let (loaded, tw) = load_snapshot(&path).unwrap();
        assert_eq!(tw, 42);
        assert_eq!(loaded.balance(&[1u8; 32]), 1000);
        assert_eq!(loaded.balance(&[2u8; 32]), 2000);
        assert_eq!(loaded.balance(&[3u8; 32]), 500);
        assert_eq!(loaded.len(), 3);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_snapshot() {
        let store = AccountStore::new();
        let dir = std::env::temp_dir();
        let path = dir.join("zero-test-empty-snapshot.bin");

        save_snapshot(&store, 0, &path).unwrap();

        let (loaded, tw) = load_snapshot(&path).unwrap();
        assert_eq!(tw, 0);
        assert_eq!(loaded.len(), 0);

        let _ = fs::remove_file(&path);
    }
}
