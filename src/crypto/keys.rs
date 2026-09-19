use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use std::fs;
use std::path::{Path, PathBuf};

const ANDROID_RSAPUBLICKEY_MODULUS_WORDS: usize = 64; // 2048 / 32 = 64 words

pub fn default_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".android").join("adbkey")
}

pub fn get_or_create_key() -> Result<RsaPrivateKey, String> {
    let key_path = default_key_path();
    if key_path.exists() {
        load_key(&key_path)
    } else {
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory: {}", e))?;
        }
        generate_and_save_key(&key_path)
    }
}

pub fn load_key(path: &Path) -> Result<RsaPrivateKey, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read key file: {}", e))?;

    // Try PKCS#8 PEM
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(&content) {
        return Ok(key);
    }
    // Try PKCS#1 PEM
    use rsa::pkcs1::DecodeRsaPrivateKey;
    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(&content) {
        return Ok(key);
    }

    Err(format!(
        "Could not parse private key from {}",
        path.display()
    ))
}

pub fn generate_and_save_key(path: &Path) -> Result<RsaPrivateKey, String> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| format!("Failed to generate RSA-2048 key: {}", e))?;

    // Encode to PKCS#8 PEM
    let pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| format!("Failed to encode private key to PKCS8 PEM: {}", e))?;

    fs::write(path, pem.as_bytes())
        .map_err(|e| format!("Failed to write private key: {}", e))?;

    // Also write public key file: path.with_extension("pub")
    let pub_path = PathBuf::from(format!("{}.pub", path.display()));
    let pub_key = RsaPublicKey::from(&private_key);
    let adb_pub_string = format_adb_public_key(&pub_key, "ruri@localhost");
    let _ = fs::write(&pub_path, adb_pub_string.as_bytes());

    Ok(private_key)
}

/// Formats an RSA public key into Android's ADB public key format:
/// "<base64 encoded android_rsapublickey_struct> user@hostname\0"
pub fn format_adb_public_key(pub_key: &RsaPublicKey, banner: &str) -> String {
    let raw_struct = serialize_android_rsapublickey(pub_key);
    let b64 = BASE64.encode(&raw_struct);
    format!("{} {}\0", b64, banner)
}

/// Serializes RsaPublicKey to Android `RSAPublicKey` binary structure (524 bytes for 2048-bit RSA):
/// struct RSAPublicKey {
///     int len;                  // Modulus length in 32-bit words (64 for 2048-bit)
///     uint32_t n0inv;           // -1 / N[0] mod 2^32
///     uint8_t n[256];           // Modulus as little-endian bytes
///     uint8_t rr[256];          // R^2 as little-endian bytes, where R = 2^(2048)
///     int exponent;             // 3 or 65537
/// };
pub fn serialize_android_rsapublickey(pub_key: &RsaPublicKey) -> Vec<u8> {
    use num_traits::One;

    let n = pub_key.n();
    let e = pub_key.e();

    let mut buf = Vec::with_capacity(524);

    // len (int, 64)
    buf.extend_from_slice(
        &(ANDROID_RSAPUBLICKEY_MODULUS_WORDS as u32).to_le_bytes(),
    );

    // Compute n0inv: -1 / N[0] mod 2^32
    // First, get N[0] (the lowest 32 bits of modulus)
    let n_bytes_le = n.to_bytes_le();
    let mut n0: u32 = 0;
    for (i, &b) in n_bytes_le.iter().take(4).enumerate() {
        n0 |= (b as u32) << (i * 8);
    }

    // Modular inverse using extended Euclidean algorithm for 32-bit
    let mut n0inv: u32 = 1;
    for _ in 0..31 {
        n0inv = n0inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(n0inv)));
    }
    n0inv = (0u32).wrapping_sub(n0inv);
    buf.extend_from_slice(&n0inv.to_le_bytes());

    // Modulus as 256 bytes little endian
    let mut n_arr = vec![0u8; 256];
    let copy_len = n_bytes_le.len().min(256);
    n_arr[..copy_len].copy_from_slice(&n_bytes_le[..copy_len]);
    buf.extend_from_slice(&n_arr);

    // rr: R^2 mod N, where R = 2^(2048)
    // R^2 = 2^(4096)
    let r: BigUint = BigUint::one() << 2048;
    let rr: BigUint = (&r * &r) % n;
    let rr_bytes_le = rr.to_bytes_le();
    let mut rr_arr = vec![0u8; 256];
    let rr_copy_len = rr_bytes_le.len().min(256);
    rr_arr[..rr_copy_len].copy_from_slice(&rr_bytes_le[..rr_copy_len]);
    buf.extend_from_slice(&rr_arr);

    // exponent (int, typically 65537)
    let e_bytes_le = e.to_bytes_le();
    let mut exp_val: u32 = 65537;
    if !e_bytes_le.is_empty() {
        let mut v: u32 = 0;
        for (i, &b) in e_bytes_le.iter().take(4).enumerate() {
            v |= (b as u32) << (i * 8);
        }
        exp_val = v;
    }
    buf.extend_from_slice(&exp_val.to_le_bytes());

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_and_adb_public_key() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let adb_pub = format_adb_public_key(&public_key, "test@host");
        assert!(adb_pub.ends_with(" test@host\0"));
        assert!(adb_pub.len() > 100);
    }
}
