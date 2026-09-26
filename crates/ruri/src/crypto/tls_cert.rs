use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use std::fs;
use std::path::{Path, PathBuf};

pub fn cert_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".android").join("adbkey_cert.der")
}

pub fn key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".android").join("adbkey.der")
}

pub fn get_or_generate_tls_cert() -> Result<(Vec<u8>, Vec<u8>), String> {
    let cp = cert_path();
    let kp = key_path();

    if cp.exists() && kp.exists() {
        let cert_der =
            fs::read(&cp).map_err(|e| format!("Failed to read cert: {}", e))?;
        let key_der =
            fs::read(&kp).map_err(|e| format!("Failed to read key: {}", e))?;
        return Ok((cert_der, key_der));
    }

    if let Some(parent) = cp.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let key_pair = KeyPair::generate()
        .map_err(|e| format!("Failed to generate keypair: {}", e))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "ruri");

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("Failed to self sign cert: {}", e))?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    let _ = fs::write(&cp, &cert_der);
    let _ = fs::write(&kp, &key_der);

    Ok((cert_der, key_der))
}
