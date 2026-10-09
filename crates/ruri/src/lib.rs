pub mod crypto;
pub mod protocol;
pub mod pty;
pub mod transport;

pub use crypto::*;
pub use protocol::*;
pub use pty::*;
pub use transport::*;

use std::io;
use std::path::Path;
use std::time::Duration;

/// High-level client for programmatic ADB operations over localhost Wireless ADB.
pub struct RuriClient {
    port: u16,
    addr: String,
}

impl RuriClient {
    /// Auto-detect the local wireless ADB daemon port and return a client.
    pub fn auto_connect() -> io::Result<Self> {
        let port = scan_local_adbd(30000, 45000).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Could not detect local wireless ADB port. Is Wireless Debugging enabled?",
            )
        })?;
        Self::with_port(port)
    }

    /// Create a client using a known port.
    pub fn with_port(port: u16) -> io::Result<Self> {
        Ok(Self {
            port,
            addr: format!("127.0.0.1:{}", port),
        })
    }

    /// Current port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Create a new low-level ADB connection.
    pub fn connect_raw(&self, timeout: Duration) -> io::Result<AdbConnection> {
        AdbConnection::connect(&self.addr, timeout)
    }

    /// Execute a command in UID 2000 shell and capture its output into a byte buffer.
    pub fn exec(&self, cmd: &str) -> io::Result<Vec<u8>> {
        let conn = self.connect_raw(Duration::from_secs(5))?;
        let mut stream = conn.into_stream();

        let local_id: u32 = 1;
        let service = format!("exec:{}", cmd);
        let open_msg = AdbMessage::open(local_id, &service);
        open_msg.write_to(&mut stream)?;

        let ok_resp = AdbMessage::read_from(&mut stream)?;
        if ok_resp.header.command != A_OKAY || ok_resp.header.arg1 != local_id {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "Command exec channel open failed (got 0x{:08X})",
                    ok_resp.header.command
                ),
            ));
        }

        let remote_id = ok_resp.header.arg0;
        let mut output = Vec::new();

        while let Ok(msg) = AdbMessage::read_from(&mut stream) {
            if msg.header.command == A_WRTE {
                output.extend_from_slice(&msg.payload);
                let ack = AdbMessage::okay(local_id, remote_id);
                let _ = ack.write_to(&mut stream);
            } else if msg.header.command == A_CLSE {
                let ack = AdbMessage::clse(local_id, remote_id);
                let _ = ack.write_to(&mut stream);
                break;
            }
        }

        Ok(output)
    }

    /// Execute a command and return stdout/stderr as a String.
    pub fn exec_str(&self, cmd: &str) -> io::Result<String> {
        let bytes = self.exec(cmd)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    /// Execute a command and stream stdout/stderr directly to the current process stdout.
    pub fn exec_stream(&self, cmd: &str) -> io::Result<i32> {
        let conn = self.connect_raw(Duration::from_secs(5))?;
        let stream = conn.into_stream();
        run_exec_command(stream, cmd)
    }

    /// Open an interactive PTY shell in the device's UID 2000 environment.
    pub fn open_shell(&self) -> io::Result<()> {
        let conn = self.connect_raw(Duration::from_secs(5))?;
        let stream = conn.into_stream();
        run_interactive_shell(stream)
    }

    /// Push an in-memory byte slice directly to a remote destination file path.
    pub fn push_bytes(
        &self,
        remote_path: &str,
        data: &[u8],
        permissions_octal: u32,
    ) -> io::Result<()> {
        let conn = self.connect_raw(Duration::from_secs(5))?;
        let mut stream = conn.into_stream();

        let local_id: u32 = 1;
        let open_msg = AdbMessage::open(local_id, "sync:");
        open_msg.write_to(&mut stream)?;

        let ok_resp = AdbMessage::read_from(&mut stream)?;
        if ok_resp.header.command != A_OKAY || ok_resp.header.arg1 != local_id {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "Sync channel open failed (got 0x{:08X})",
                    ok_resp.header.command
                ),
            ));
        }

        let remote_id = ok_resp.header.arg0;

        // 1. Send SEND request: format is "remote_path,mode"
        let send_param = format!("{},{:04o}", remote_path, permissions_octal);
        let mut send_payload = Vec::with_capacity(8 + send_param.len());
        send_payload.extend_from_slice(ID_SEND);
        send_payload.extend_from_slice(&(send_param.len() as u32).to_le_bytes());
        send_payload.extend_from_slice(send_param.as_bytes());

        let wrte = AdbMessage::wrte(local_id, remote_id, send_payload);
        wrte.write_to(&mut stream)?;
        read_sync_ack(&mut stream)?;

        // 2. Stream DATA chunks
        for chunk in data.chunks(SYNC_DATA_MAX) {
            let mut data_payload = Vec::with_capacity(8 + chunk.len());
            data_payload.extend_from_slice(ID_DATA);
            data_payload.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            data_payload.extend_from_slice(chunk);

            let wrte = AdbMessage::wrte(local_id, remote_id, data_payload);
            wrte.write_to(&mut stream)?;
            read_sync_ack(&mut stream)?;
        }

        // 3. Send DONE packet
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let mut done_payload = Vec::with_capacity(8);
        done_payload.extend_from_slice(ID_DONE);
        done_payload.extend_from_slice(&now.to_le_bytes());

        let wrte = AdbMessage::wrte(local_id, remote_id, done_payload);
        wrte.write_to(&mut stream)?;
        read_sync_ack(&mut stream)?;

        // 4. Read response
        let resp = AdbMessage::read_from(&mut stream)?;
        if resp.header.command == A_WRTE && resp.payload.len() >= 8 {
            let id = &resp.payload[0..4];
            if id == ID_FAIL {
                let msg_len =
                    u32::from_le_bytes(resp.payload[4..8].try_into().unwrap())
                        as usize;
                let err_msg = String::from_utf8_lossy(
                    &resp.payload[8..(8 + msg_len).min(resp.payload.len())],
                );
                return Err(io::Error::other(format!(
                    "Sync push failed: {}",
                    err_msg
                )));
            }
        }

        let clse = AdbMessage::clse(local_id, remote_id);
        let _ = clse.write_to(&mut stream);
        Ok(())
    }

    /// Push a local file to the remote path.
    pub fn push_file(&self, local_path: &Path, remote_path: &str) -> io::Result<()> {
        let conn = self.connect_raw(Duration::from_secs(5))?;
        let stream = conn.into_stream();
        push_file(stream, local_path, remote_path)
    }

    /// Pull a remote file to a local path.
    pub fn pull_file(&self, remote_path: &str, local_path: &Path) -> io::Result<()> {
        let conn = self.connect_raw(Duration::from_secs(5))?;
        let stream = conn.into_stream();
        pull_file(stream, remote_path, local_path)
    }
}

fn read_sync_ack(stream: &mut AdbStream) -> io::Result<()> {
    let ack = AdbMessage::read_from(stream)?;
    if ack.header.command == A_OKAY {
        Ok(())
    } else if ack.header.command == A_CLSE {
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Sync stream closed by server",
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// C-ABI / FFI exports for libruri.so
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct RuriResult {
    pub data: *mut u8,
    pub len: usize,
    pub success: bool,
}

#[unsafe(no_mangle)]
pub extern "C" fn ruri_scan_port() -> u16 {
    scan_local_adbd(30000, 45000).unwrap_or(0)
}

/// Executes a shell command via `ruri` over ADB.
///
/// # Safety
///
/// `cmd_ptr` must be a valid, null-terminated C string pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ruri_exec_cmd(cmd_ptr: *const libc::c_char) -> RuriResult {
    if cmd_ptr.is_null() {
        return RuriResult {
            data: std::ptr::null_mut(),
            len: 0,
            success: false,
        };
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(cmd_ptr) };
    let cmd_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return RuriResult {
                data: std::ptr::null_mut(),
                len: 0,
                success: false,
            };
        }
    };

    let client = match RuriClient::auto_connect() {
        Ok(c) => c,
        Err(_) => {
            return RuriResult {
                data: std::ptr::null_mut(),
                len: 0,
                success: false,
            };
        }
    };

    match client.exec(cmd_str) {
        Ok(mut out) => {
            out.shrink_to_fit();
            let ptr = out.as_mut_ptr();
            let len = out.len();
            std::mem::forget(out);
            RuriResult {
                data: ptr,
                len,
                success: true,
            }
        }
        Err(_) => RuriResult {
            data: std::ptr::null_mut(),
            len: 0,
            success: false,
        },
    }
}

/// Frees an allocated `RuriResult` buffer.
///
/// # Safety
///
/// `res.data` must point to memory previously allocated by `ruri_exec_cmd` with the corresponding `res.len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ruri_free_result(res: RuriResult) {
    if !res.data.is_null() && res.len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(res.data, res.len, res.len);
        }
    }
}
