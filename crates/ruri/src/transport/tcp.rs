use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError,
    SignatureScheme, StreamOwned,
};

use crate::crypto::{
    format_adb_public_key, get_or_create_key, get_or_generate_tls_cert, sign_token,
};
use crate::protocol::{
    A_AUTH, A_CNXN, A_STLS, AUTH_TYPE_RSAPUBLICKEY, AUTH_TYPE_SIGNATURE,
    AUTH_TYPE_TOKEN, AdbMessage,
};
use rsa::RsaPublicKey;

#[derive(Debug)]
struct DummyServerVerifier;

impl ServerCertVerifier for DummyServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

pub enum AdbStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for AdbStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            AdbStream::Plain(s) => s.read(buf),
            AdbStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for AdbStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            AdbStream::Plain(s) => s.write(buf),
            AdbStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            AdbStream::Plain(s) => s.flush(),
            AdbStream::Tls(s) => s.flush(),
        }
    }
}

pub struct AdbConnection {
    stream: AdbStream,
    pub banner: String,
    pub max_payload: u32,
}

impl AdbConnection {
    pub fn connect(addr: &str, timeout: Duration) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;

        let mut conn = Self {
            stream: AdbStream::Plain(stream),
            banner: String::new(),
            max_payload: 1024 * 1024,
        };

        conn.handshake(addr)?;
        if let AdbStream::Plain(ref s) = conn.stream {
            let _ = s.set_read_timeout(None);
            let _ = s.set_write_timeout(None);
        }
        Ok(conn)
    }

    fn handshake(&mut self, addr: &str) -> io::Result<()> {
        let private_key = get_or_create_key()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let public_key = RsaPublicKey::from(&private_key);

        // 1. Send CNXN
        let banner_str = "host::ruri\0";
        let cnxn = AdbMessage::cnxn(banner_str);
        cnxn.write_to(&mut self.stream)?;

        // 2. Read response
        let response = AdbMessage::read_from(&mut self.stream)?;

        // Check for A_STLS (Wireless Debugging on Android 11+)
        if response.header.command == A_STLS {
            self.upgrade_to_tls(addr)?;
            // Inside TLS tunnel, re-send CNXN
            let cnxn_tls = AdbMessage::cnxn(banner_str);
            cnxn_tls.write_to(&mut self.stream)?;

            let tls_response = AdbMessage::read_from(&mut self.stream)?;
            if tls_response.header.command == A_CNXN {
                self.banner =
                    String::from_utf8_lossy(&tls_response.payload).to_string();
                self.max_payload = tls_response.header.arg1;
                return Ok(());
            }

            return self.handle_auth(tls_response, &private_key, &public_key);
        }

        if response.header.command == A_CNXN {
            self.banner = String::from_utf8_lossy(&response.payload).to_string();
            self.max_payload = response.header.arg1;
            return Ok(());
        }

        self.handle_auth(response, &private_key, &public_key)
    }

    fn upgrade_to_tls(&mut self, _addr: &str) -> io::Result<()> {
        let plain_stream = match std::mem::replace(
            &mut self.stream,
            AdbStream::Plain(unsafe { std::mem::zeroed() }),
        ) {
            AdbStream::Plain(s) => s,
            AdbStream::Tls(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Already TLS",
                ));
            }
        };

        let (cert_der, key_der) = get_or_generate_tls_cert()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let certs = vec![CertificateDer::from(cert_der)];
        let key = PrivateKeyDer::try_from(key_der).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid private key: {:?}", e),
            )
        })?;

        // Reply STLS ack back to server
        let mut ack_stream = plain_stream;
        let stls_msg = AdbMessage::stls();
        stls_msg.write_to(&mut ack_stream)?;

        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DummyServerVerifier))
        .with_client_auth_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let server_name = ServerName::try_from("localhost").map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
        })?;

        let client = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let tls_stream = StreamOwned::new(client, ack_stream);
        self.stream = AdbStream::Tls(Box::new(tls_stream));

        Ok(())
    }

    fn handle_auth(
        &mut self,
        response: AdbMessage,
        private_key: &rsa::RsaPrivateKey,
        public_key: &RsaPublicKey,
    ) -> io::Result<()> {
        if response.header.command != A_AUTH
            || response.header.arg0 != AUTH_TYPE_TOKEN
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected AUTH token, got command 0x{:08X}",
                    response.header.command
                ),
            ));
        }

        let token = response.payload;
        let signature = sign_token(private_key, &token)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let auth_resp = AdbMessage::new(A_AUTH, AUTH_TYPE_SIGNATURE, 0, signature);
        auth_resp.write_to(&mut self.stream)?;

        let resp2 = AdbMessage::read_from(&mut self.stream)?;
        if resp2.header.command == A_CNXN {
            self.banner = String::from_utf8_lossy(&resp2.payload).to_string();
            self.max_payload = resp2.header.arg1;
            return Ok(());
        }

        if resp2.header.command == A_AUTH {
            let pub_key_str = format_adb_public_key(public_key, "ruri@localhost");
            let auth_pub = AdbMessage::new(
                A_AUTH,
                AUTH_TYPE_RSAPUBLICKEY,
                0,
                pub_key_str.into_bytes(),
            );
            auth_pub.write_to(&mut self.stream)?;

            let resp3 = AdbMessage::read_from(&mut self.stream)?;
            if resp3.header.command == A_CNXN {
                self.banner = String::from_utf8_lossy(&resp3.payload).to_string();
                self.max_payload = resp3.header.arg1;
                return Ok(());
            }
        }

        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ADB authentication failed or rejected by device",
        ))
    }

    pub fn send(&mut self, msg: &AdbMessage) -> io::Result<()> {
        msg.write_to(&mut self.stream)
    }

    pub fn recv(&mut self) -> io::Result<AdbMessage> {
        AdbMessage::read_from(&mut self.stream)
    }

    pub fn into_stream(self) -> AdbStream {
        self.stream
    }
}
