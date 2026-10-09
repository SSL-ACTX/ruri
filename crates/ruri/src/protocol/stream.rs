use crate::protocol::{A_CLSE, A_OKAY, A_WRTE, AdbMessage};
use crate::pty::RawTerminal;
use crate::transport::AdbStream;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

pub fn run_exec_command(stream: AdbStream, cmd: &str) -> io::Result<i32> {
    let mut stdout = io::stdout();
    run_exec_to_writer(stream, cmd, &mut stdout)
}

pub fn run_exec_to_file(
    stream: AdbStream,
    cmd: &str,
    path: &str,
) -> io::Result<i32> {
    let mut file = File::create(path)?;
    run_exec_to_writer(stream, cmd, &mut file)
}

pub fn run_exec_to_writer<W: Write>(
    mut stream: AdbStream,
    cmd: &str,
    writer: &mut W,
) -> io::Result<i32> {
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

    while let Ok(msg) = AdbMessage::read_from(&mut stream) {
        if msg.header.command == A_WRTE {
            let _ = writer.write_all(&msg.payload);
            let _ = writer.flush();
            let ack = AdbMessage::okay(local_id, remote_id);
            let _ = ack.write_to(&mut stream);
        } else if msg.header.command == A_CLSE {
            let ack = AdbMessage::clse(local_id, remote_id);
            let _ = ack.write_to(&mut stream);
            break;
        }
    }

    Ok(0)
}

pub fn run_exec_piped_input<R: Read>(
    mut stream: AdbStream,
    cmd: &str,
    mut reader: R,
) -> io::Result<i32> {
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
    let mut in_buf = [0u8; 16384];

    // Stream input from reader to adbd
    loop {
        match reader.read(&mut in_buf) {
            Ok(0) => break,
            Ok(n) => {
                let wrte =
                    AdbMessage::wrte(local_id, remote_id, in_buf[..n].to_vec());
                wrte.write_to(&mut stream)?;
                // Wait for OKAY backpressure
                if let Ok(ack) = AdbMessage::read_from(&mut stream) {
                    if ack.header.command == A_CLSE {
                        break;
                    }
                } else {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    // Read remaining output until CLSE
    let mut stdout = io::stdout();
    while let Ok(msg) = AdbMessage::read_from(&mut stream) {
        if msg.header.command == A_WRTE {
            let _ = stdout.write_all(&msg.payload);
            let _ = stdout.flush();
            let ack = AdbMessage::okay(local_id, remote_id);
            let _ = ack.write_to(&mut stream);
        } else if msg.header.command == A_CLSE {
            let ack = AdbMessage::clse(local_id, remote_id);
            let _ = ack.write_to(&mut stream);
            break;
        }
    }

    Ok(0)
}

pub fn run_interactive_shell(mut stream: AdbStream) -> io::Result<()> {
    let local_id: u32 = 1;
    let _raw_term = RawTerminal::new()?;

    // Request interactive PTY with TERM environment variable if possible
    let service = "shell,v2,pty,TERM=xterm-256color:";
    let open_msg = AdbMessage::open(local_id, service);
    open_msg.write_to(&mut stream)?;

    let mut ok_resp = AdbMessage::read_from(&mut stream)?;
    // If shell,v2 is not supported by legacy adbd, fall back to plain shell:
    if ok_resp.header.command != A_OKAY {
        let fallback_msg = AdbMessage::open(local_id, "shell:");
        fallback_msg.write_to(&mut stream)?;
        ok_resp = AdbMessage::read_from(&mut stream)?;
    }

    if ok_resp.header.command != A_OKAY || ok_resp.header.arg1 != local_id {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "Shell channel open failed (got 0x{:08X})",
                ok_resp.header.command
            ),
        ));
    }

    let remote_id = ok_resp.header.arg0;
    let running = Arc::new(AtomicBool::new(true));

    let mut read_stream = stream.try_clone()?;
    let running_reader = Arc::clone(&running);

    // Background reader from adbd -> local stdout
    let reader_handle = thread::spawn(move || {
        let mut stdout = io::stdout();
        while running_reader.load(Ordering::Relaxed) {
            match AdbMessage::read_from(&mut read_stream) {
                Ok(msg) => {
                    if msg.header.command == A_WRTE {
                        let _ = stdout.write_all(&msg.payload);
                        let _ = stdout.flush();
                        let ack = AdbMessage::okay(local_id, remote_id);
                        if ack.write_to(&mut read_stream).is_err() {
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

    // Foreground non-blocking poll on stdin
    let stdin_fd = io::stdin().as_raw_fd();
    let mut stdin = io::stdin();
    let mut in_buf = [0u8; 1024];

    while running.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd {
            fd: stdin_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let ret = unsafe { libc::poll(&mut pfd, 1, 50) };
        if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
            match stdin.read(&mut in_buf) {
                Ok(0) => break,
                Ok(n) => {
                    let wrte =
                        AdbMessage::wrte(local_id, remote_id, in_buf[..n].to_vec());
                    if wrte.write_to(&mut stream).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(_) => break,
            }
        }
    }

    running.store(false, Ordering::Relaxed);
    let clse = AdbMessage::clse(local_id, remote_id);
    let _ = clse.write_to(&mut stream);
    let _ = reader_handle.join();

    Ok(())
}
