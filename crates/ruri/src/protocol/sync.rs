use crate::protocol::{A_CLSE, A_OKAY, A_WRTE, AdbMessage};
use crate::transport::AdbStream;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

pub const ID_STAT: &[u8; 4] = b"STAT";
pub const ID_SEND: &[u8; 4] = b"SEND";
pub const ID_RECV: &[u8; 4] = b"RECV";
pub const ID_DATA: &[u8; 4] = b"DATA";
pub const ID_DONE: &[u8; 4] = b"DONE";
pub const ID_OKAY: &[u8; 4] = b"OKAY";
pub const ID_FAIL: &[u8; 4] = b"FAIL";

pub const SYNC_DATA_MAX: usize = 64 * 1024; // 64KB sync chunk

pub fn push_file(
    mut stream: AdbStream,
    local_path: &Path,
    remote_path: &str,
) -> io::Result<()> {
    let mut file = File::open(local_path)?;
    let metadata = file.metadata()?;
    let total_size = metadata.len();
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

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

    // 1. Send SEND request: format is "remote_path,0644"
    let send_param = format!("{},0644", remote_path);
    let mut send_payload = Vec::with_capacity(8 + send_param.len());
    send_payload.extend_from_slice(ID_SEND);
    send_payload.extend_from_slice(&(send_param.len() as u32).to_le_bytes());
    send_payload.extend_from_slice(send_param.as_bytes());

    let wrte = AdbMessage::wrte(local_id, remote_id, send_payload);
    wrte.write_to(&mut stream)?;
    read_ack(&mut stream)?;

    // 2. Stream DATA chunks
    let mut buffer = [0u8; SYNC_DATA_MAX];
    let mut transferred: u64 = 0;

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let mut data_payload = Vec::with_capacity(8 + n);
        data_payload.extend_from_slice(ID_DATA);
        data_payload.extend_from_slice(&(n as u32).to_le_bytes());
        data_payload.extend_from_slice(&buffer[..n]);

        let wrte = AdbMessage::wrte(local_id, remote_id, data_payload);
        wrte.write_to(&mut stream)?;
        read_ack(&mut stream)?;

        transferred += n as u64;
        let pct = if total_size > 0 {
            (transferred as f64 / total_size as f64) * 100.0
        } else {
            100.0
        };
        print!(
            "\r[*] Uploading: {:.1}% ({}/{} bytes)",
            pct, transferred, total_size
        );
        let _ = io::stdout().flush();
    }
    println!();

    // 3. Send DONE packet
    let mut done_payload = Vec::with_capacity(8);
    done_payload.extend_from_slice(ID_DONE);
    done_payload.extend_from_slice(&mtime.to_le_bytes());

    let wrte = AdbMessage::wrte(local_id, remote_id, done_payload);
    wrte.write_to(&mut stream)?;
    read_ack(&mut stream)?;

    // 4. Read OKAY / FAIL response from adbd
    let resp = AdbMessage::read_from(&mut stream)?;
    if resp.header.command == A_WRTE && resp.payload.len() >= 8 {
        let id = &resp.payload[0..4];
        if id == ID_FAIL {
            let msg_len =
                u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()) as usize;
            let err_msg = String::from_utf8_lossy(
                &resp.payload[8..(8 + msg_len).min(resp.payload.len())],
            );
            return Err(io::Error::other(format!("Sync failed: {}", err_msg)));
        }
    }

    // Close sync stream
    let clse = AdbMessage::clse(local_id, remote_id);
    let _ = clse.write_to(&mut stream);

    Ok(())
}

pub fn pull_file(
    mut stream: AdbStream,
    remote_path: &str,
    local_path: &Path,
) -> io::Result<()> {
    let mut file = File::create(local_path)?;
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

    // 1. Send RECV request
    let mut recv_payload = Vec::with_capacity(8 + remote_path.len());
    recv_payload.extend_from_slice(ID_RECV);
    recv_payload.extend_from_slice(&(remote_path.len() as u32).to_le_bytes());
    recv_payload.extend_from_slice(remote_path.as_bytes());

    let wrte = AdbMessage::wrte(local_id, remote_id, recv_payload);
    wrte.write_to(&mut stream)?;

    // 2. Read DATA chunks until DONE
    let mut received: u64 = 0;
    let mut stream_buf = Vec::new();

    loop {
        let msg = AdbMessage::read_from(&mut stream)?;
        if msg.header.command == A_CLSE {
            break;
        }
        if msg.header.command != A_WRTE {
            continue;
        }

        // Send OKAY ack
        let ack = AdbMessage::okay(local_id, remote_id);
        ack.write_to(&mut stream)?;

        stream_buf.extend_from_slice(&msg.payload);

        let mut offset = 0;

        while offset + 8 <= stream_buf.len() {
            let chunk_id = &stream_buf[offset..offset + 4];
            let chunk_len = u32::from_le_bytes(
                stream_buf[offset + 4..offset + 8].try_into().unwrap(),
            ) as usize;

            if chunk_id == ID_DONE {
                println!();
                let clse = AdbMessage::clse(local_id, remote_id);
                let _ = clse.write_to(&mut stream);
                return Ok(());
            } else if chunk_id == ID_FAIL {
                if offset + 8 + chunk_len > stream_buf.len() {
                    break;
                }
                let err_msg = String::from_utf8_lossy(
                    &stream_buf[offset + 8..offset + 8 + chunk_len],
                );
                return Err(io::Error::other(format!(
                    "Sync pull failed: {}",
                    err_msg
                )));
            } else if chunk_id == ID_DATA {
                if offset + 8 + chunk_len > stream_buf.len() {
                    // Need more bytes to complete this chunk
                    break;
                }
                file.write_all(&stream_buf[offset + 8..offset + 8 + chunk_len])?;
                received += chunk_len as u64;
                offset += 8 + chunk_len;
                print!("\r[*] Downloading: {} bytes received", received);
                let _ = io::stdout().flush();
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unknown sync chunk ID: {:?}", chunk_id),
                ));
            }
        }

        if offset > 0 {
            stream_buf.drain(..offset);
        }
    }

    println!();
    let clse = AdbMessage::clse(local_id, remote_id);
    let _ = clse.write_to(&mut stream);

    Ok(())
}

fn read_ack(stream: &mut AdbStream) -> io::Result<()> {
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
