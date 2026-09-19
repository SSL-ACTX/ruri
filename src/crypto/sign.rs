use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey};

const SHA1_DIGEST_INFO_PREFIX: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
    0x04, 0x14,
];

/// Android adbd expects RSASSA-PKCS1-v1_5 where the token is ALREADY treated as the 20-byte SHA-1 digest.
/// Standard RSA signers hash the token a second time (double-hashing), causing signature verification
/// to fail and forcing Android to display an "Allow USB debugging?" authorization popup every time.
/// By properly prepending the ASN.1 SHA-1 DigestInfo prefix and applying PKCS#1 v1.5 padding directly,
/// the signature is accepted instantly and permanently by adbd.
pub fn sign_token(
    private_key: &RsaPrivateKey,
    token: &[u8],
) -> Result<Vec<u8>, String> {
    let key_size = 256; // 2048-bit RSA = 256 bytes

    let mut prefixed =
        Vec::with_capacity(SHA1_DIGEST_INFO_PREFIX.len() + token.len());
    prefixed.extend_from_slice(&SHA1_DIGEST_INFO_PREFIX);
    prefixed.extend_from_slice(token);

    if prefixed.len() > key_size - 11 {
        return Err("Token is too long for 2048-bit RSA".to_string());
    }

    let pad_len = key_size - 3 - prefixed.len();
    let mut padded = Vec::with_capacity(key_size);
    padded.push(0x00);
    padded.push(0x01);
    padded.resize(padded.len() + pad_len, 0xff);
    padded.push(0x00);
    padded.extend_from_slice(&prefixed);

    let m = BigUint::from_bytes_be(&padded);
    let d = private_key.d();
    let n = private_key.n();

    // Modular exponentiation: m^d mod n
    let s = m.modpow(d, n);
    let mut sig = s.to_bytes_be();

    // Ensure signature is exactly key_size bytes (left-padded with zeros if needed)
    if sig.len() < key_size {
        let mut full_sig = vec![0u8; key_size - sig.len()];
        full_sig.extend_from_slice(&sig);
        sig = full_sig;
    }

    Ok(sig)
}
