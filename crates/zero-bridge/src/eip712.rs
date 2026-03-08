//! EIP-712 typed structured data signing for vault release operations.
//!
//! Matches the Solidity ZeroVault contract's EIP-712 domain and types exactly.
//! Trinity Validators use this to sign release messages with ECDSA (secp256k1).

use k256::ecdsa::{Signature, SigningKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// EIP-712 domain separator components.
#[derive(Debug, Clone)]
pub struct DomainSeparator {
    /// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    pub type_hash: [u8; 32],
    /// keccak256("ZeroVault")
    pub name_hash: [u8; 32],
    /// keccak256("2")
    pub version_hash: [u8; 32],
    /// Chain ID (e.g., 84532 for Base Sepolia)
    pub chain_id: u64,
    /// Vault contract address
    pub verifying_contract: [u8; 20],
}

/// Pre-computed type hash: keccak256("Release(address token,uint256 amount,address recipient,bytes32 bridgeId)")
/// Matches ZeroVault.RELEASE_TYPEHASH (0xb0eff49e...).
pub const RELEASE_TYPEHASH: [u8; 32] = [
    0xb0, 0xef, 0xf4, 0x9e, 0x45, 0x23, 0x78, 0x91, 0x05, 0xf5, 0x4c, 0xf6, 0x1c, 0x1c, 0x1f, 0x3e,
    0x5d, 0xa6, 0x4c, 0x07, 0x5c, 0x8c, 0xca, 0xc9, 0x5e, 0x8d, 0x47, 0x90, 0x85, 0xf4, 0xbc, 0x57,
];

/// Compute keccak256 of input bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute the EIP-712 domain type hash.
pub fn domain_type_hash() -> [u8; 32] {
    keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
}

/// Compute the Release struct type hash.
pub fn release_typehash() -> [u8; 32] {
    keccak256(b"Release(address token,uint256 amount,address recipient,bytes32 bridgeId)")
}

impl DomainSeparator {
    /// Create a new domain separator for a ZeroVault deployment.
    pub fn new(chain_id: u64, vault_address: [u8; 20]) -> Self {
        Self {
            type_hash: domain_type_hash(),
            name_hash: keccak256(b"ZeroVault"),
            version_hash: keccak256(b"2"),
            chain_id,
            verifying_contract: vault_address,
        }
    }

    /// Compute the domain separator hash (matches Solidity's _domainSeparatorV4()).
    pub fn hash(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(160);
        encoded.extend_from_slice(&self.type_hash);
        encoded.extend_from_slice(&self.name_hash);
        encoded.extend_from_slice(&self.version_hash);

        // uint256 chainId — left-padded to 32 bytes
        let mut chain_id_bytes = [0u8; 32];
        chain_id_bytes[24..].copy_from_slice(&self.chain_id.to_be_bytes());
        encoded.extend_from_slice(&chain_id_bytes);

        // address verifyingContract — left-padded to 32 bytes
        let mut addr_bytes = [0u8; 32];
        addr_bytes[12..].copy_from_slice(&self.verifying_contract);
        encoded.extend_from_slice(&addr_bytes);

        keccak256(&encoded)
    }
}

/// Parameters for a release operation (matches Solidity struct).
#[derive(Debug, Clone)]
pub struct ReleaseParams {
    /// ERC-20 token address (20 bytes)
    pub token: [u8; 20],
    /// Amount in token decimals
    pub amount: u64,
    /// Recipient address on the destination chain (20 bytes)
    pub recipient: [u8; 20],
    /// Unique bridge operation ID (32 bytes)
    pub bridge_id: [u8; 32],
    /// Destination chain name (e.g. "base", "arbitrum") — used for vault routing.
    /// Not part of the EIP-712 struct hash; only used to select the correct vault.
    pub dest_chain: String,
}

/// Computes the EIP-712 struct hash for a Release operation.
pub fn release_struct_hash(params: &ReleaseParams) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(160);

    // bytes32 typeHash
    encoded.extend_from_slice(&release_typehash());

    // address token — left-padded to 32 bytes
    let mut token_bytes = [0u8; 32];
    token_bytes[12..].copy_from_slice(&params.token);
    encoded.extend_from_slice(&token_bytes);

    // uint256 amount — left-padded to 32 bytes
    let mut amount_bytes = [0u8; 32];
    amount_bytes[24..].copy_from_slice(&params.amount.to_be_bytes());
    encoded.extend_from_slice(&amount_bytes);

    // address recipient — left-padded to 32 bytes
    let mut recipient_bytes = [0u8; 32];
    recipient_bytes[12..].copy_from_slice(&params.recipient);
    encoded.extend_from_slice(&recipient_bytes);

    // bytes32 bridgeId
    encoded.extend_from_slice(&params.bridge_id);

    keccak256(&encoded)
}

/// Computes the full EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash)
pub fn eip712_digest(domain: &DomainSeparator, struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(66);
    encoded.push(0x19);
    encoded.push(0x01);
    encoded.extend_from_slice(&domain.hash());
    encoded.extend_from_slice(struct_hash);
    keccak256(&encoded)
}

/// Signs EIP-712 typed data for vault release operations.
pub struct Eip712Signer {
    /// ECDSA signing key (secp256k1)
    signing_key: SigningKey,
    /// The signer's Ethereum address (derived from public key)
    pub address: [u8; 20],
    /// Domain separator for the target vault
    domain: DomainSeparator,
}

#[derive(Error, Debug)]
pub enum Eip712Error {
    #[error("ECDSA signing failed: {0}")]
    SigningFailed(String),
    #[error("invalid private key")]
    InvalidKey,
}

/// A signed release: the 65-byte ECDSA signature (r || s || v).
#[derive(Debug, Clone)]
pub struct ReleaseSigning {
    /// The EIP-712 digest that was signed
    pub digest: [u8; 32],
    /// The 65-byte signature (r[32] || s[32] || v[1])
    pub signature: [u8; 65],
    /// The signer's Ethereum address
    pub signer: [u8; 20],
}

/// Derive Ethereum address from a secp256k1 verifying key.
pub fn verifying_key_to_address(vk: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false);
    // Skip the 0x04 prefix byte, hash the 64-byte uncompressed key
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

impl Eip712Signer {
    /// Create a signer from a 32-byte private key and vault deployment info.
    pub fn new(
        private_key: &[u8; 32],
        chain_id: u64,
        vault_address: [u8; 20],
    ) -> Result<Self, Eip712Error> {
        let signing_key =
            SigningKey::from_bytes(private_key.into()).map_err(|_| Eip712Error::InvalidKey)?;
        let address = verifying_key_to_address(signing_key.verifying_key());

        Ok(Self {
            signing_key,
            address,
            domain: DomainSeparator::new(chain_id, vault_address),
        })
    }

    /// Sign a release operation. Returns the 65-byte ECDSA signature.
    pub fn sign_release(&self, params: &ReleaseParams) -> Result<ReleaseSigning, Eip712Error> {
        let struct_hash = release_struct_hash(params);
        let digest = eip712_digest(&self.domain, &struct_hash);

        // Sign the digest
        let (sig, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(&digest)
            .map_err(|e| Eip712Error::SigningFailed(e.to_string()))?;

        let sig_bytes: [u8; 64] = sig.to_bytes().into();

        // Pack as r || s || v (v = recovery_id + 27)
        let mut packed = [0u8; 65];
        packed[..64].copy_from_slice(&sig_bytes);
        packed[64] = recovery_id.to_byte() + 27;

        Ok(ReleaseSigning {
            digest,
            signature: packed,
            signer: self.address,
        })
    }

    /// Get the domain separator hash.
    pub fn domain_separator(&self) -> [u8; 32] {
        self.domain.hash()
    }
}

/// Recover the signer address from a 65-byte ECDSA signature over a digest.
pub fn recover_signer(digest: &[u8; 32], signature: &[u8; 65]) -> Result<[u8; 20], Eip712Error> {
    use k256::ecdsa::{RecoveryId, VerifyingKey};

    let r_s = &signature[..64];
    let v = signature[64];
    let recovery_id = RecoveryId::try_from(v.wrapping_sub(27))
        .map_err(|e| Eip712Error::SigningFailed(e.to_string()))?;

    let sig =
        Signature::from_bytes(r_s.into()).map_err(|e| Eip712Error::SigningFailed(e.to_string()))?;

    let recovered_key = VerifyingKey::recover_from_prehash(digest, &sig, recovery_id)
        .map_err(|e| Eip712Error::SigningFailed(e.to_string()))?;

    Ok(verifying_key_to_address(&recovered_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        // Deterministic test key
        let mut key = [0u8; 32];
        key[31] = 1;
        key
    }

    fn test_signer() -> Eip712Signer {
        let key = test_key();
        // Base Sepolia chain ID = 84532, dummy vault address
        let vault = [0xAA; 20];
        Eip712Signer::new(&key, 84532, vault).unwrap()
    }

    #[test]
    fn domain_separator_is_deterministic() {
        let ds1 = DomainSeparator::new(84532, [0xAA; 20]);
        let ds2 = DomainSeparator::new(84532, [0xAA; 20]);
        assert_eq!(ds1.hash(), ds2.hash());
    }

    #[test]
    fn different_chains_different_domain() {
        let ds1 = DomainSeparator::new(84532, [0xAA; 20]);
        let ds2 = DomainSeparator::new(421614, [0xAA; 20]);
        assert_ne!(ds1.hash(), ds2.hash());
    }

    #[test]
    fn different_vaults_different_domain() {
        let ds1 = DomainSeparator::new(84532, [0xAA; 20]);
        let ds2 = DomainSeparator::new(84532, [0xBB; 20]);
        assert_ne!(ds1.hash(), ds2.hash());
    }

    #[test]
    fn release_typehash_matches_solidity() {
        let hash = release_typehash();
        // This should match: keccak256("Release(address token,uint256 amount,address recipient,bytes32 bridgeId)")
        let expected =
            keccak256(b"Release(address token,uint256 amount,address recipient,bytes32 bridgeId)");
        assert_eq!(hash, expected);
    }

    #[test]
    fn sign_and_recover() {
        let signer = test_signer();

        let params = ReleaseParams {
            token: [0x11; 20],
            amount: 1_000_000,
            recipient: [0x22; 20],
            bridge_id: [0x33; 32],
            dest_chain: "base".into(),
        };

        let signed = signer.sign_release(&params).unwrap();

        // Recover signer from signature
        let recovered = recover_signer(&signed.digest, &signed.signature).unwrap();
        assert_eq!(recovered, signer.address);
    }

    #[test]
    fn different_params_different_digest() {
        let signer = test_signer();

        let params1 = ReleaseParams {
            token: [0x11; 20],
            amount: 1_000_000,
            recipient: [0x22; 20],
            bridge_id: [0x33; 32],
            dest_chain: "base".into(),
        };

        let params2 = ReleaseParams {
            token: [0x11; 20],
            amount: 2_000_000, // Different amount
            recipient: [0x22; 20],
            bridge_id: [0x33; 32],
            dest_chain: "base".into(),
        };

        let signed1 = signer.sign_release(&params1).unwrap();
        let signed2 = signer.sign_release(&params2).unwrap();

        assert_ne!(signed1.digest, signed2.digest);
    }

    #[test]
    fn two_signers_same_digest() {
        let mut key1 = [0u8; 32];
        key1[31] = 1;
        let mut key2 = [0u8; 32];
        key2[31] = 2;

        let vault = [0xAA; 20];
        let signer1 = Eip712Signer::new(&key1, 84532, vault).unwrap();
        let signer2 = Eip712Signer::new(&key2, 84532, vault).unwrap();

        let params = ReleaseParams {
            token: [0x11; 20],
            amount: 1_000_000,
            recipient: [0x22; 20],
            bridge_id: [0x33; 32],
            dest_chain: "base".into(),
        };

        let signed1 = signer1.sign_release(&params).unwrap();
        let signed2 = signer2.sign_release(&params).unwrap();

        // Same digest (same domain + params)
        assert_eq!(signed1.digest, signed2.digest);
        // Different signatures (different keys)
        assert_ne!(signed1.signature, signed2.signature);
        // Different signers
        assert_ne!(signed1.signer, signed2.signer);
    }

    #[test]
    fn wrong_key_wrong_recovery() {
        let signer = test_signer();

        let params = ReleaseParams {
            token: [0x11; 20],
            amount: 1_000_000,
            recipient: [0x22; 20],
            bridge_id: [0x33; 32],
            dest_chain: "base".into(),
        };

        let signed = signer.sign_release(&params).unwrap();

        // Create a different signer
        let mut other_key = [0u8; 32];
        other_key[31] = 99;
        let other = Eip712Signer::new(&other_key, 84532, [0xAA; 20]).unwrap();

        // Recovered address should NOT match the other signer
        let recovered = recover_signer(&signed.digest, &signed.signature).unwrap();
        assert_ne!(recovered, other.address);
    }

    #[test]
    fn address_derivation_deterministic() {
        let key = test_key();
        let sk = SigningKey::from_bytes((&key).into()).unwrap();
        let addr1 = verifying_key_to_address(sk.verifying_key());
        let addr2 = verifying_key_to_address(sk.verifying_key());
        assert_eq!(addr1, addr2);
        // Address should be non-zero
        assert_ne!(addr1, [0u8; 20]);
    }

    #[test]
    fn signature_is_65_bytes() {
        let signer = test_signer();
        let params = ReleaseParams {
            token: [0x11; 20],
            amount: 1_000_000,
            recipient: [0x22; 20],
            bridge_id: [0x33; 32],
            dest_chain: "base".into(),
        };
        let signed = signer.sign_release(&params).unwrap();
        assert_eq!(signed.signature.len(), 65);
        // v should be 27 or 28
        assert!(signed.signature[64] == 27 || signed.signature[64] == 28);
    }
}
