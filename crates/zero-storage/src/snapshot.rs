use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use tracing::info;
use zero_types::{Account, PubKey};

use crate::AccountStore;

/// Snapshot format version. Increment when format changes.
const SNAPSHOT_VERSION: u32 = 2;

/// V1 header: version(4) + account_count(8) + total_written(8) = 20 bytes.
const HEADER_SIZE_V1: usize = 20;

/// V2 header: V1 header + fee_pool(8) + bridge_reserve(8) + protocol_reserve(8) = 44 bytes.
const HEADER_SIZE_V2: usize = 44;

/// Per-account record: pubkey(32) + account(48) = 80 bytes.
const RECORD_SIZE: usize = 80;

/// Data returned from loading a snapshot.
pub struct SnapshotData {
    pub store: AccountStore,
    pub total_written: u64,
    pub fee_pool: u64,
    pub bridge_reserve: u64,
    pub protocol_reserve: u64,
}

/// Save account state to a binary snapshot file (v2 format).
///
/// Format:
///   [4 bytes]  version (u32 LE) = 2
///   [8 bytes]  account count (u64 LE)
///   [8 bytes]  total_written from transfer log (u64 LE, for resume)
///   [8 bytes]  fee_pool (u64 LE)
///   [8 bytes]  bridge_reserve (u64 LE)
///   [8 bytes]  protocol_reserve (u64 LE)
///   For each account:
///     [32 bytes] public key
///     [48 bytes] account state (Account::to_bytes())
pub fn save_snapshot(
    store: &AccountStore,
    total_written: u64,
    fee_pool: u64,
    bridge_reserve: u64,
    protocol_reserve: u64,
    path: &Path,
) -> io::Result<()> {
    let tmp_path = path.with_extension("tmp");

    let mut file = fs::File::create(&tmp_path)?;

    // Collect all accounts (DashMap iteration)
    let accounts: Vec<(PubKey, Account)> = store.iter_accounts();
    let count = accounts.len() as u64;

    // Write v2 header
    file.write_all(&SNAPSHOT_VERSION.to_le_bytes())?;
    file.write_all(&count.to_le_bytes())?;
    file.write_all(&total_written.to_le_bytes())?;
    file.write_all(&fee_pool.to_le_bytes())?;
    file.write_all(&bridge_reserve.to_le_bytes())?;
    file.write_all(&protocol_reserve.to_le_bytes())?;

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
        fee_pool,
        bridge_reserve,
        protocol_reserve,
        path = %path.display(),
        "Snapshot saved (v2)"
    );

    Ok(())
}

/// Load account state from a snapshot file (supports v1 and v2).
pub fn load_snapshot(path: &Path) -> Result<SnapshotData, String> {
    let data =
        fs::read(path).map_err(|e| format!("Failed to read snapshot {}: {}", path.display(), e))?;

    if data.len() < HEADER_SIZE_V1 {
        return Err("Snapshot file too small for header".into());
    }

    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());

    let (header_size, fee_pool, bridge_reserve, protocol_reserve) = match version {
        1 => {
            info!("Loading v1 snapshot (reserves default to 0)");
            (HEADER_SIZE_V1, 0u64, 0u64, 0u64)
        }
        2 => {
            if data.len() < HEADER_SIZE_V2 {
                return Err("Snapshot v2 file too small for header".into());
            }
            let fp = u64::from_le_bytes(data[20..28].try_into().unwrap());
            let br = u64::from_le_bytes(data[28..36].try_into().unwrap());
            let pr = u64::from_le_bytes(data[36..44].try_into().unwrap());
            (HEADER_SIZE_V2, fp, br, pr)
        }
        _ => {
            return Err(format!("Unsupported snapshot version: {}", version));
        }
    };

    let count = u64::from_le_bytes(data[4..12].try_into().unwrap()) as usize;
    let total_written = u64::from_le_bytes(data[12..20].try_into().unwrap());

    let expected_size = header_size + count * RECORD_SIZE;
    if data.len() < expected_size {
        return Err(format!(
            "Snapshot truncated: expected {} bytes, got {}",
            expected_size,
            data.len()
        ));
    }

    let store = AccountStore::with_capacity(count);
    let mut offset = header_size;

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
        version,
        accounts = count,
        total_written,
        fee_pool,
        bridge_reserve,
        protocol_reserve,
        path = %path.display(),
        "Snapshot loaded"
    );

    Ok(SnapshotData {
        store,
        total_written,
        fee_pool,
        bridge_reserve,
        protocol_reserve,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip_v2() {
        let store = AccountStore::new();
        store.mint(&[1u8; 32], 1000);
        store.mint(&[2u8; 32], 2000);
        store.mint(&[3u8; 32], 500);

        let dir = std::env::temp_dir();
        let path = dir.join("zero-test-snapshot-v2.bin");

        save_snapshot(&store, 42, 100, 200, 300, &path).unwrap();

        let snap = load_snapshot(&path).unwrap();
        assert_eq!(snap.total_written, 42);
        assert_eq!(snap.fee_pool, 100);
        assert_eq!(snap.bridge_reserve, 200);
        assert_eq!(snap.protocol_reserve, 300);
        assert_eq!(snap.store.balance(&[1u8; 32]), 1000);
        assert_eq!(snap.store.balance(&[2u8; 32]), 2000);
        assert_eq!(snap.store.balance(&[3u8; 32]), 500);
        assert_eq!(snap.store.len(), 3);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn empty_snapshot_v2() {
        let store = AccountStore::new();
        let dir = std::env::temp_dir();
        let path = dir.join("zero-test-empty-snapshot-v2.bin");

        save_snapshot(&store, 0, 0, 0, 0, &path).unwrap();

        let snap = load_snapshot(&path).unwrap();
        assert_eq!(snap.total_written, 0);
        assert_eq!(snap.fee_pool, 0);
        assert_eq!(snap.bridge_reserve, 0);
        assert_eq!(snap.protocol_reserve, 0);
        assert_eq!(snap.store.len(), 0);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn v1_backward_compat() {
        // Build a v1 snapshot manually: 20-byte header + accounts
        let store = AccountStore::new();
        store.mint(&[0xAA; 32], 5000);
        let accounts: Vec<(PubKey, Account)> = store.iter_accounts();

        let dir = std::env::temp_dir();
        let path = dir.join("zero-test-snapshot-v1-compat.bin");

        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // version 1
        data.extend_from_slice(&(accounts.len() as u64).to_le_bytes());
        data.extend_from_slice(&99u64.to_le_bytes()); // total_written
        for (pk, acct) in &accounts {
            data.extend_from_slice(pk);
            data.extend_from_slice(&acct.to_bytes());
        }
        fs::write(&path, &data).unwrap();

        let snap = load_snapshot(&path).unwrap();
        assert_eq!(snap.total_written, 99);
        assert_eq!(snap.fee_pool, 0); // v1 defaults
        assert_eq!(snap.bridge_reserve, 0);
        assert_eq!(snap.protocol_reserve, 0);
        assert_eq!(snap.store.balance(&[0xAA; 32]), 5000);

        let _ = fs::remove_file(&path);
    }
}
