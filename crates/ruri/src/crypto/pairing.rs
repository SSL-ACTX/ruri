use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest::{self, Context, SHA512};
use ring::hkdf::{self, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, StreamOwned};

use crate::crypto::keys::{format_adb_public_key, get_or_create_key};
use crate::crypto::tls_cert::get_or_generate_tls_cert;

// Protocol constants from AOSP pairing_connection.h & pairing.proto
const CURRENT_KEY_HEADER_VERSION: u8 = 1;
const PACKET_TYPE_SPAKE2_MSG: u8 = 0;
const PACKET_TYPE_PEER_INFO: u8 = 1;

const CLIENT_ROLE_NAME: &[u8] = b"adb pair client\0";
const SERVER_ROLE_NAME: &[u8] = b"adb pair server\0";
const EXPORTED_KEY_LABEL: &[u8] = b"adb-label\0";
const HKDF_AES_INFO: &[u8] = b"adb pairing_auth aes-128-gcm key";

const PEER_INFO_SIZE: usize = 8192;
const ADB_RSA_PUB_KEY_TYPE: u8 = 0;

struct AesKeyLen;
impl hkdf::KeyType for AesKeyLen {
    fn len(&self) -> usize {
        16
    }
}

fn derive_aes_key(key_material: &[u8; 64]) -> io::Result<LessSafeKey> {
    let salt = hkdf::Salt::new(HKDF_SHA256, &[]);
    let prk = salt.extract(key_material);
    let okm = prk.expand(&[HKDF_AES_INFO], AesKeyLen).map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "HKDF expansion failed")
    })?;
    let mut aes_key = [0u8; 16];
    okm.fill(&mut aes_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HKDF fill failed"))?;
    let unbound = UnboundKey::new(&AES_128_GCM, &aes_key).map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "Failed to create AES key")
    })?;
    Ok(LessSafeKey::new(unbound))
}

// Base generator point M for Curve25519 SPAKE2 in BoringSSL / AOSP
const POINT_M_BYTES: [u8; 32] = [
    0x5a, 0xda, 0x7e, 0x4b, 0xf6, 0xdd, 0xd9, 0xad, 0xb6, 0x62, 0x6d, 0x32, 0x13,
    0x1c, 0x6b, 0x5c, 0x51, 0xa1, 0xe3, 0x47, 0xa3, 0x47, 0x8f, 0x53, 0xcf, 0xcf,
    0x44, 0x1b, 0x88, 0xee, 0xd1, 0x2e,
];

// Base generator point N for Curve25519 SPAKE2 in BoringSSL / AOSP
const POINT_N_BYTES: [u8; 32] = [
    0x10, 0xe3, 0xdf, 0x0a, 0xe3, 0x7d, 0x8e, 0x7a, 0x99, 0xb5, 0xfe, 0x74, 0xb4,
    0x46, 0x72, 0x10, 0x3d, 0xbd, 0xdc, 0xbd, 0x06, 0xaf, 0x68, 0x0d, 0x71, 0x32,
    0x9a, 0x11, 0x69, 0x3b, 0xc7, 0x78,
];

// Curve25519 subgroup prime order L in little-endian
const ORDER_L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde,
    0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn scalar_mul_integer(
    point: &EdwardsPoint,
    mut scalar: num_bigint::BigUint,
) -> EdwardsPoint {
    let mut result = EdwardsPoint::default(); // identity point (0, 1)
    let mut base = *point;
    let zero = num_bigint::BigUint::from(0u32);
    while scalar > zero {
        if (scalar.to_u32_digits().first().copied().unwrap_or(0) & 1) != 0 {
            result = result + base;
        }
        base = base + base;
        scalar >>= 1;
    }
    result
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Spake2Role {
    Alice,
    Bob,
}

pub struct Spake2Party {
    role: Spake2Role,
    my_name: Vec<u8>,
    their_name: Vec<u8>,
    priv_scalar: Scalar,
    my_msg: [u8; 32],
    password_hash: [u8; 64],
    s_int: num_bigint::BigUint,
    point_m: EdwardsPoint,
    point_n: EdwardsPoint,
}

impl Spake2Party {
    pub fn new(
        role: Spake2Role,
        my_name: &[u8],
        their_name: &[u8],
        password: &[u8],
    ) -> io::Result<Self> {
        let point_m =
            CompressedEdwardsY(POINT_M_BYTES)
                .decompress()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid SPAKE2 point M",
                    )
                })?;
        let point_n =
            CompressedEdwardsY(POINT_N_BYTES)
                .decompress()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid SPAKE2 point N",
                    )
                })?;

        // 1. Generate ephemeral private key: (rand mod L) * 8
        let rng = SystemRandom::new();
        let mut rand_bytes = [0u8; 64];
        rng.fill(&mut rand_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Random generation failed")
        })?;
        let rand_scalar = Scalar::from_bytes_mod_order_wide(&rand_bytes);
        let priv_scalar = rand_scalar * Scalar::from(8u64);

        // 2. Compute ephemeral public point P = private_key * G
        let p_point = ED25519_BASEPOINT_POINT * priv_scalar;

        // 3. Hash password to SHA-512
        let hash = digest::digest(&SHA512, password);
        let mut password_hash = [0u8; 64];
        password_hash.copy_from_slice(hash.as_ref());

        // 4. Compute password scalar with BoringSSL cofactor clearing
        let w_scalar = Scalar::from_bytes_mod_order_wide(&password_hash);
        let mut s_int = num_bigint::BigUint::from_bytes_le(w_scalar.as_bytes());
        let l_int = num_bigint::BigUint::from_bytes_le(&ORDER_L_BYTES);

        let mut order = l_int;

        if (s_int.to_u32_digits().first().copied().unwrap_or(0) & 1) != 0 {
            s_int += &order;
        }
        order *= 2u32;
        if (s_int.to_u32_digits().first().copied().unwrap_or(0) & 2) != 0 {
            s_int += &order;
        }
        order *= 2u32;
        if (s_int.to_u32_digits().first().copied().unwrap_or(0) & 4) != 0 {
            s_int += &order;
        }

        // 5. Mask point: Alice uses M, Bob uses N
        let mask = match role {
            Spake2Role::Alice => scalar_mul_integer(&point_m, s_int.clone()),
            Spake2Role::Bob => scalar_mul_integer(&point_n, s_int.clone()),
        };

        // 6. Output message: P* = P + mask
        let my_msg_point = p_point + mask;
        let my_msg = my_msg_point.compress().to_bytes();

        Ok(Self {
            role,
            my_name: my_name.to_vec(),
            their_name: their_name.to_vec(),
            priv_scalar,
            my_msg,
            password_hash,
            s_int,
            point_m,
            point_n,
        })
    }

    pub fn my_msg(&self) -> &[u8; 32] {
        &self.my_msg
    }

    pub fn process_msg(&self, their_msg: &[u8]) -> io::Result<[u8; 64]> {
        if their_msg.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid peer message length",
            ));
        }
        let mut msg_arr = [0u8; 32];
        msg_arr.copy_from_slice(their_msg);

        let q_star = CompressedEdwardsY(msg_arr).decompress().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Peer point is not on curve")
        })?;

        // Unmask peer: Alice uses N, Bob uses M
        let peer_mask = match self.role {
            Spake2Role::Alice => {
                scalar_mul_integer(&self.point_n, self.s_int.clone())
            }
            Spake2Role::Bob => scalar_mul_integer(&self.point_m, self.s_int.clone()),
        };

        let q_point = q_star - peer_mask;
        let dh_shared_point = q_point * self.priv_scalar;
        let dh_shared = dh_shared_point.compress().to_bytes();

        // Transcript hash using SHA-512 with 8-byte little-endian length prefixes
        let mut sha = Context::new(&SHA512);
        if self.role == Spake2Role::Alice {
            update_with_u64_len(&mut sha, &self.my_name);
            update_with_u64_len(&mut sha, &self.their_name);
            update_with_u64_len(&mut sha, &self.my_msg);
            update_with_u64_len(&mut sha, their_msg);
        } else {
            update_with_u64_len(&mut sha, &self.their_name);
            update_with_u64_len(&mut sha, &self.my_name);
            update_with_u64_len(&mut sha, their_msg);
            update_with_u64_len(&mut sha, &self.my_msg);
        }
        update_with_u64_len(&mut sha, &dh_shared);
        update_with_u64_len(&mut sha, &self.password_hash);

        let final_hash = sha.finish();
        let mut key_material = [0u8; 64];
        key_material.copy_from_slice(final_hash.as_ref());

        Ok(key_material)
    }
}

fn update_with_u64_len(hasher: &mut Context, data: &[u8]) {
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Executes the full native AOSP Wireless Pairing protocol in pure Rust.
pub fn pair_device(addr: &str, password: &str, timeout: Duration) -> io::Result<()> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;

    // 1. Setup client TLS credentials
    let (cert_der, key_der) = get_or_generate_tls_cert()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let cert_pki = CertificateDer::from(cert_der);
    let key_pki = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_client_auth_cert(vec![cert_pki], key_pki)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    config.resumption = rustls::client::Resumption::disabled();

    let server_name = "localhost".try_into().unwrap();
    let client_conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut tls_stream = StreamOwned::new(client_conn, tcp);
    while tls_stream.conn.is_handshaking() {
        tls_stream.conn.complete_io(&mut tls_stream.sock)?;
    }

    // 2. Export 64 bytes of key material from TLS 1.3 session
    let mut exported_key = [0u8; 64];
    tls_stream
        .conn
        .export_keying_material(&mut exported_key, EXPORTED_KEY_LABEL, None)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("TLS key export failed: {}", e),
            )
        })?;

    // 3. Form final SPAKE2 password = [ASCII PIN] + [64 bytes TLS key material]
    let mut full_password = Vec::with_capacity(password.len() + exported_key.len());
    full_password.extend_from_slice(password.as_bytes());
    full_password.extend_from_slice(&exported_key);

    // 4. Initialize pure Rust SPAKE2 party (Client = Alice)
    let spake2 = Spake2Party::new(
        Spake2Role::Alice,
        CLIENT_ROLE_NAME,
        SERVER_ROLE_NAME,
        &full_password,
    )?;

    let my_msg = spake2.my_msg();

    // 5. Send SPAKE2 Client Message (Type 0)
    let mut header = [0u8; 6];
    header[0] = CURRENT_KEY_HEADER_VERSION;
    header[1] = PACKET_TYPE_SPAKE2_MSG;
    header[2..6].copy_from_slice(&(my_msg.len() as u32).to_be_bytes());
    tls_stream.write_all(&header)?;
    tls_stream.write_all(my_msg)?;
    tls_stream.flush()?;

    // 6. Read SPAKE2 Server Message (Type 0)
    let mut resp_header = [0u8; 6];
    tls_stream.read_exact(&mut resp_header)?;
    if resp_header[0] != CURRENT_KEY_HEADER_VERSION
        || resp_header[1] != PACKET_TYPE_SPAKE2_MSG
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SPAKE2 response packet from device",
        ));
    }
    let their_payload_len =
        u32::from_be_bytes(resp_header[2..6].try_into().unwrap()) as usize;
    let mut their_msg = vec![0u8; their_payload_len];
    tls_stream.read_exact(&mut their_msg)?;

    let key_material = spake2.process_msg(&their_msg)?;

    // 7. Derive AES-128-GCM key using HKDF-SHA256
    let cipher = derive_aes_key(&key_material)?;

    // 8. Build PeerInfo packet containing RSA public key
    let priv_key =
        get_or_create_key().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let adb_pub_string =
        format_adb_public_key(&priv_key.to_public_key(), "ruri@localhost");

    let mut peer_info = vec![0u8; PEER_INFO_SIZE];
    peer_info[0] = ADB_RSA_PUB_KEY_TYPE;
    let pub_bytes = adb_pub_string.as_bytes();
    let copy_len = pub_bytes.len().min(PEER_INFO_SIZE - 1);
    peer_info[1..1 + copy_len].copy_from_slice(&pub_bytes[..copy_len]);

    // Encrypt PeerInfo (sequence = 0)
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    cipher
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut peer_info)
        .map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to encrypt PeerInfo")
        })?;
    let encrypted_peer_info = peer_info;

    // 9. Send encrypted PEER_INFO (Type 1)
    header[0] = CURRENT_KEY_HEADER_VERSION;
    header[1] = PACKET_TYPE_PEER_INFO;
    header[2..6].copy_from_slice(&(encrypted_peer_info.len() as u32).to_be_bytes());
    tls_stream.write_all(&header)?;
    tls_stream.write_all(&encrypted_peer_info)?;
    tls_stream.flush()?;

    // 10. Read device's encrypted PEER_INFO response
    tls_stream.read_exact(&mut resp_header)?;
    if resp_header[0] != CURRENT_KEY_HEADER_VERSION
        || resp_header[1] != PACKET_TYPE_PEER_INFO
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid PeerInfo response packet from device",
        ));
    }
    let dev_peer_info_len =
        u32::from_be_bytes(resp_header[2..6].try_into().unwrap()) as usize;
    let mut dev_encrypted = vec![0u8; dev_peer_info_len];
    tls_stream.read_exact(&mut dev_encrypted)?;

    let dev_nonce = Nonce::assume_unique_for_key([0u8; 12]);
    let dev_decrypted = cipher
        .open_in_place(dev_nonce, Aad::empty(), &mut dev_encrypted)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Peer verification failed",
            )
        })?;

    if dev_decrypted.len() != PEER_INFO_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unexpected PeerInfo response size from device",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ServerConfig;
    use rustls::server::ServerConnection;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_pure_rust_spake2_mutual_derivation() {
        let password = b"pure_rust_secret_123";
        let alice = Spake2Party::new(
            Spake2Role::Alice,
            CLIENT_ROLE_NAME,
            SERVER_ROLE_NAME,
            password,
        )
        .unwrap();
        let bob = Spake2Party::new(
            Spake2Role::Bob,
            SERVER_ROLE_NAME,
            CLIENT_ROLE_NAME,
            password,
        )
        .unwrap();

        let alice_key = alice.process_msg(bob.my_msg()).unwrap();
        let bob_key = bob.process_msg(alice.my_msg()).unwrap();

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_pure_rust_spake2_pairing_handshake_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let test_addr = format!("127.0.0.1:{}", port);
        let test_pin = "852963";

        // Setup mock pairing server (adbd) thread in pure Rust
        let handle = thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().unwrap();
            let (cert_der, key_der) = get_or_generate_tls_cert().unwrap();
            let cert_pki = CertificateDer::from(cert_der);
            let key_pki = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());

            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_pki], key_pki)
                .unwrap();

            let server_conn =
                ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut tls_stream = StreamOwned::new(server_conn, tcp_stream);
            while tls_stream.conn.is_handshaking() {
                tls_stream.conn.complete_io(&mut tls_stream.sock).unwrap();
            }

            // Export keying material
            let mut srv_exported = [0u8; 64];
            tls_stream
                .conn
                .export_keying_material(&mut srv_exported, EXPORTED_KEY_LABEL, None)
                .unwrap();

            let mut srv_password = Vec::new();
            srv_password.extend_from_slice(test_pin.as_bytes());
            srv_password.extend_from_slice(&srv_exported);

            // Server SPAKE2 (Bob)
            let srv_spake2 = Spake2Party::new(
                Spake2Role::Bob,
                SERVER_ROLE_NAME,
                CLIENT_ROLE_NAME,
                &srv_password,
            )
            .unwrap();

            let srv_msg = srv_spake2.my_msg();

            // Read client SPAKE2 message
            let mut header = [0u8; 6];
            tls_stream.read_exact(&mut header).unwrap();
            assert_eq!(header[0], CURRENT_KEY_HEADER_VERSION);
            assert_eq!(header[1], PACKET_TYPE_SPAKE2_MSG);
            let client_len =
                u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
            let mut client_msg = vec![0u8; client_len];
            tls_stream.read_exact(&mut client_msg).unwrap();

            // Send server SPAKE2 message
            header[0] = CURRENT_KEY_HEADER_VERSION;
            header[1] = PACKET_TYPE_SPAKE2_MSG;
            header[2..6].copy_from_slice(&(srv_msg.len() as u32).to_be_bytes());
            tls_stream.write_all(&header).unwrap();
            tls_stream.write_all(srv_msg).unwrap();
            tls_stream.flush().unwrap();

            // Derive key material
            let srv_key = srv_spake2.process_msg(&client_msg).unwrap();

            // Init server AES cipher
            let cipher = derive_aes_key(&srv_key).unwrap();

            // Read client encrypted PeerInfo
            tls_stream.read_exact(&mut header).unwrap();
            assert_eq!(header[0], CURRENT_KEY_HEADER_VERSION);
            assert_eq!(header[1], PACKET_TYPE_PEER_INFO);
            let enc_len =
                u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
            let mut enc_payload = vec![0u8; enc_len];
            tls_stream.read_exact(&mut enc_payload).unwrap();

            let nonce = Nonce::assume_unique_for_key([0u8; 12]);
            let decrypted_peer_info = cipher
                .open_in_place(nonce, Aad::empty(), &mut enc_payload)
                .unwrap();
            assert_eq!(decrypted_peer_info.len(), PEER_INFO_SIZE);
            assert_eq!(decrypted_peer_info[0], ADB_RSA_PUB_KEY_TYPE);

            // Send server encrypted PeerInfo reply
            let mut srv_peer_info = vec![1u8; PEER_INFO_SIZE];
            let srv_nonce = Nonce::assume_unique_for_key([0u8; 12]);
            cipher
                .seal_in_place_append_tag(
                    srv_nonce,
                    Aad::empty(),
                    &mut srv_peer_info,
                )
                .unwrap();
            let encrypted_srv = srv_peer_info;
            header[2..6]
                .copy_from_slice(&(encrypted_srv.len() as u32).to_be_bytes());
            tls_stream.write_all(&header).unwrap();
            tls_stream.write_all(&encrypted_srv).unwrap();
            tls_stream.flush().unwrap();
        });

        // Test client run
        let pair_result = pair_device(&test_addr, test_pin, Duration::from_secs(5));
        assert!(
            pair_result.is_ok(),
            "pair_device failed: {:?}",
            pair_result.err()
        );

        handle.join().unwrap();
    }
}
