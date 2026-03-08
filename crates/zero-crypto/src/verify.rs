use ed25519_dalek::{Signature as DalekSig, VerifyingKey};
use zero_types::{Transfer, ZeroError};

/// Verify the Ed25519 signature on a transfer.
///
/// Checks that the signature in the transfer was produced by the `from` key
/// over the signing bytes (from ++ to ++ amount ++ nonce).
pub fn verify_transfer(transfer: &Transfer) -> Result<(), ZeroError> {
    let vk =
        VerifyingKey::from_bytes(&transfer.from).map_err(|e| ZeroError::Crypto(e.to_string()))?;
    let sig = DalekSig::from_bytes(&transfer.signature);
    vk.verify_strict(&transfer.signing_bytes(), &sig)
        .map_err(|_| ZeroError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPair;

    #[test]
    fn valid_signature_passes() {
        let kp = KeyPair::generate();
        let mut tx = Transfer {
            from: kp.public_key(),
            to: [2u8; 32],
            amount: 100,
            nonce: 1,
            signature: [0u8; 64],
        };
        tx.signature = kp.sign_transfer(&tx);
        assert!(verify_transfer(&tx).is_ok());
    }

    #[test]
    fn tampered_amount_fails() {
        let kp = KeyPair::generate();
        let mut tx = Transfer {
            from: kp.public_key(),
            to: [2u8; 32],
            amount: 100,
            nonce: 1,
            signature: [0u8; 64],
        };
        tx.signature = kp.sign_transfer(&tx);
        tx.amount = 200; // tamper
        assert!(verify_transfer(&tx).is_err());
    }

    #[test]
    fn wrong_signer_fails() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let mut tx = Transfer {
            from: kp1.public_key(),
            to: [2u8; 32],
            amount: 100,
            nonce: 1,
            signature: [0u8; 64],
        };
        // Sign with kp2 but from is kp1
        tx.signature = kp2.sign_transfer(&tx);
        assert!(verify_transfer(&tx).is_err());
    }
}
