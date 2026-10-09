use crate::protocol::{A_CLSE, A_OKAY, A_WRTE, AdbMessage};
use crate::transport::{AdbConnection, AdbStream};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Starts a local TCP listener on `local_port` and forwards every inbound connection
/// directly into the remote device's `remote_target` (e.g. `tcp:8080`) over ADB.
pub fn start_port_forward(
    adbd_addr: &str,
    local_port: u16,
    remote_target: &str,
) -> io::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port))?;
    println!(
        "[+] Forwarding localhost:{} -> device '{}'...",
        local_port, remote_target
    );

    let adbd_addr = adbd_addr.to_string();
    let remote_target = remote_target.to_string();

    for incoming in listener.incoming() {
        match incoming {
            Ok(local_stream) => {
                let addr_clone = adbd_addr.clone();
                let target_clone = remote_target.clone();

                thread::spawn(move || {
                    if let Err(e) = forward_single_connection(
                        &addr_clone,
                        local_stream,
                        &target_clone,
                    ) {
                        eprintln!("[-] Forward error: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("[-] Accept error: {}", e);
            }
        }
    }

    Ok(())
}

fn forward_single_connection(
    adbd_addr: &str,
    mut client_stream: TcpStream,
    remote_target: &str,
) -> io::Result<()> {
    client_stream.set_nodelay(true)?;

    // Connect and establish ADB session
    let conn = AdbConnection::connect(adbd_addr, Duration::from_secs(3))?;
    let mut adb_stream: AdbStream = conn.into_stream();

    let local_id: u32 = 1;
    let service = if remote_target.starts_with("tcp:") {
        remote_target.to_string()
    } else {
        format!("tcp:{}", remote_target)
    };

    let open_msg = AdbMessage::open(local_id, &service);
    open_msg.write_to(&mut adb_stream)?;

    let ok_resp = AdbMessage::read_from(&mut adb_stream)?;
    if ok_resp.header.command != A_OKAY || ok_resp.header.arg1 != local_id {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "Failed to open remote service '{}' (got 0x{:08X})",
                service, ok_resp.header.command
            ),
        ));
    }

    let remote_id = ok_resp.header.arg0;
    let running = Arc::new(AtomicBool::new(true));

    let mut adb_read_stream = adb_stream.try_clone()?;
    let mut client_write_stream = client_stream.try_clone()?;
    let running_reader = Arc::clone(&running);

    // Thread 1: Read ADB WRTE packets and write raw bytes into client_stream
    let adb_to_client = thread::spawn(move || {
        while running_reader.load(Ordering::Relaxed) {
            match AdbMessage::read_from(&mut adb_read_stream) {
                Ok(msg) => {
                    if msg.header.command == A_WRTE {
                        if client_write_stream.write_all(&msg.payload).is_err() {
                            break;
                        }
                        let _ = client_write_stream.flush();
                        let ack = AdbMessage::okay(local_id, remote_id);
                        if ack.write_to(&mut adb_read_stream).is_err() {
                            break;
                        }
                    } else if msg.header.command == A_CLSE {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        running_reader.store(false, Ordering::Relaxed);
    });

    // Thread 2: Read raw bytes from client_stream and package as ADB WRTE
    let mut buf = [0u8; 16384];
    while running.load(Ordering::Relaxed) {
        match client_stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let wrte = AdbMessage::wrte(local_id, remote_id, buf[..n].to_vec());
                if wrte.write_to(&mut adb_stream).is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    running.store(false, Ordering::Relaxed);
    let clse = AdbMessage::clse(local_id, remote_id);
    let _ = clse.write_to(&mut adb_stream);
    let _ = adb_to_client.join();

    Ok(())
}
