use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zero_types::{PubKey, Signature};

/// An Ed25519 keypair for signing transfers.
pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Restore from a 32-byte secret key.
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
        }
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> PubKey {
        self.signing.verifying_key().to_bytes()
    }

    /// The 32-byte secret key.
    pub fn secret_key(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Sign arbitrary data, returning a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message).to_bytes()
    }

    /// Sign a transfer's signing bytes (72 bytes: from ++ to ++ amount ++ nonce).
    pub fn sign_transfer(&self, transfer: &zero_types::Transfer) -> Signature {
        self.sign(&transfer.signing_bytes())
    }

    /// Get the ed25519-dalek verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign() {
        let kp = KeyPair::generate();
        let msg = b"test message";
        let sig = kp.sign(msg);
        assert_eq!(sig.len(), 64);

        let vk = VerifyingKey::from_bytes(&kp.public_key()).unwrap();
        let sig_obj = ed25519_dalek::Signature::from_bytes(&sig);
        assert!(vk.verify_strict(msg, &sig_obj).is_ok());
    }

    #[test]
    fn from_secret_roundtrip() {
        let kp1 = KeyPair::generate();
        let secret = kp1.secret_key();
        let kp2 = KeyPair::from_secret(&secret);
        assert_eq!(kp1.public_key(), kp2.public_key());
    }
}
