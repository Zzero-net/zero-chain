use std::fs;
use std::path::Path;

use crate::keypair::KeyPair;

/// Generate a new keypair and save the secret key to a file.
/// The file contains the 32-byte secret as hex.
pub fn generate_and_save(path: &Path) -> std::io::Result<KeyPair> {
    let kp = KeyPair::generate();
    let hex = hex::encode(kp.secret_key());
    fs::write(path, hex)?;
    Ok(kp)
}

/// Load a keypair from a secret key file (hex-encoded 32 bytes).
pub fn load(path: &Path) -> Result<KeyPair, String> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read key file {}: {}", path.display(), e))?;

    let hex_str = contents.trim();
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex in key file: {}", e))?;

    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Key file must contain exactly 32 bytes (64 hex chars)".to_string())?;

    Ok(KeyPair::from_secret(&secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_key_file() {
        let kp = KeyPair::generate();
        let hex_str = hex::encode(kp.secret_key());

        // Write to a temp path
        let dir = std::env::temp_dir();
        let path = dir.join("zero-test-key.hex");
        fs::write(&path, &hex_str).unwrap();

        // Load back
        let kp2 = load(&path).unwrap();
        assert_eq!(kp.public_key(), kp2.public_key());

        // Clean up
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn generate_and_reload() {
        let dir = std::env::temp_dir();
        let path = dir.join("zero-test-gen-key.hex");

        let kp1 = generate_and_save(&path).unwrap();
        let kp2 = load(&path).unwrap();
        assert_eq!(kp1.public_key(), kp2.public_key());

        let _ = fs::remove_file(&path);
    }
}
