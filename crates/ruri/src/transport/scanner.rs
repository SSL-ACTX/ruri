use crate::protocol::{A_AUTH, A_CNXN, A_STLS, AdbHeader, AdbMessage};
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::Duration;

pub fn last_port_cache_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".ruri").join("last_port")
}

pub fn read_cached_port() -> Option<u16> {
    let path = last_port_cache_path();
    if let Ok(content) = fs::read_to_string(path) {
        content.trim().parse::<u16>().ok()
    } else {
        None
    }
}

pub fn save_cached_port(port: u16) {
    let path = last_port_cache_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, port.to_string());
}

pub fn is_adb_port(port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let cnxn = AdbMessage::cnxn("host::test\0");
    if cnxn.write_to(&mut stream).is_err() {
        return false;
    }

    let mut header_buf = [0u8; AdbHeader::SIZE];
    use std::io::Read;
    if stream.read_exact(&mut header_buf).is_err() {
        return false;
    }

    if let Ok(header) = AdbHeader::from_bytes(&header_buf) {
        header.command == A_AUTH
            || header.command == A_CNXN
            || header.command == A_STLS
    } else {
        false
    }
}

pub fn scan_local_adbd(start_port: u16, end_port: u16) -> Option<u16> {
    // Check standard 5555 first!
    if is_adb_port(5555, Duration::from_millis(50)) {
        save_cached_port(5555);
        return Some(5555);
    }

    if let Some(cached) = read_cached_port()
        && is_adb_port(cached, Duration::from_millis(50))
    {
        return Some(cached);
    }

    // Try fast zero-scan mDNS discovery (_adb-tls-connect._tcp.local)
    if let Some(mdns_port) =
        super::mdns::discover_adbd_mdns(Duration::from_millis(250))
        && is_adb_port(mdns_port, Duration::from_millis(100))
    {
        save_cached_port(mdns_port);
        return Some(mdns_port);
    }

    let found = Arc::new(AtomicU16::new(0));
    let worker_count = 32;
    let total_ports = (end_port - start_port + 1) as usize;
    let chunk_size = total_ports.div_ceil(worker_count);

    let mut handles = Vec::new();

    for w in 0..worker_count {
        let found = Arc::clone(&found);
        let p_start = start_port + (w * chunk_size) as u16;
        let p_end = (p_start + chunk_size as u16).min(end_port + 1);

        handles.push(thread::spawn(move || {
            let timeout = Duration::from_millis(15);
            for port in p_start..p_end {
                if found.load(Ordering::Relaxed) != 0 {
                    break;
                }
                let addr = SocketAddr::from(([127, 0, 0, 1], port));
                if let Ok(stream) = TcpStream::connect_timeout(&addr, timeout) {
                    drop(stream);
                    if is_adb_port(port, Duration::from_millis(60)) {
                        found.store(port, Ordering::SeqCst);
                        break;
                    }
                }
            }
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    let res = found.load(Ordering::SeqCst);
    if res != 0 {
        save_cached_port(res);
        Some(res)
    } else {
        None
    }
}
