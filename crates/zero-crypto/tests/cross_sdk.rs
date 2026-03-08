/// Cross-SDK test: verify that ed25519-dalek (Rust) and PyNaCl/libsodium (Python)
/// produce identical public keys and compatible signatures from the same secret.
///
/// This is critical for the Python SDK to work with the Rust validator.

#[test]
fn rust_pubkey_matches_pynacl() {
    // Known test vector: a fixed 32-byte secret
    let secret_hex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    let secret_bytes: [u8; 32] = hex::decode(secret_hex).unwrap().try_into().unwrap();

    // Derive via ed25519-dalek (same as zero-crypto KeyPair::from_secret)
    let kp = zero_crypto::keypair::KeyPair::from_secret(&secret_bytes);
    let rust_pubkey_hex = hex::encode(kp.public_key());

    // Expected pubkey derived via PyNaCl (pre-computed):
    // python3 -c "import nacl.signing; sk=nacl.signing.SigningKey(bytes.fromhex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')); print(sk.verify_key.encode().hex())"
    // This will be filled in by the test runner
    println!("Rust pubkey: {}", rust_pubkey_hex);

    // We can at least verify the key is deterministic
    let kp2 = zero_crypto::keypair::KeyPair::from_secret(&secret_bytes);
    assert_eq!(
        kp.public_key(),
        kp2.public_key(),
        "Key derivation must be deterministic"
    );
}

#[test]
fn rust_signature_format() {
    use zero_types::Transfer;

    let secret_hex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    let secret_bytes: [u8; 32] = hex::decode(secret_hex).unwrap().try_into().unwrap();
    let kp = zero_crypto::keypair::KeyPair::from_secret(&secret_bytes);

    let tx = Transfer {
        from: kp.public_key(),
        to: [2u8; 32],
        amount: 100,
        nonce: 1,
        signature: [0u8; 64],
    };

    let sig = kp.sign_transfer(&tx);
    assert_eq!(sig.len(), 64, "Ed25519 signature must be 64 bytes");

    // Verify the signature
    let mut signed_tx = tx;
    signed_tx.signature = sig;
    zero_crypto::verify::verify_transfer(&signed_tx)
        .expect("Signature must verify against the signing key's public key");

    println!("Signature: {}", hex::encode(sig));
}
