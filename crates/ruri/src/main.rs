use std::env;
use std::fs::File;
use std::path::Path;
use std::process::{Command, exit};
use std::time::Duration;

pub mod crypto;
pub mod protocol;
pub mod pty;
pub mod transport;

use protocol::{
    pull_file, push_file, run_exec_command, run_exec_piped_input, run_exec_to_file,
    run_interactive_shell,
};
use transport::{AdbConnection, scan_local_adbd};

fn print_usage() {
    eprintln!(
        r#"ruri: Native Pure-Rust Localhost Wireless ADB Engine

USAGE:
    ruri [COMMAND] [ARGS...]

CORE COMMANDS:
    run <cmd> [args...]   Run command transparently intercepting POSIX fs syscalls
    shell                 Open interactive UID 2000 shell
    exec <command>        Execute command and pipe stdout/stderr
    pair [port] [code]    One-time pairing setup (interactive if args omitted)
    scan                  Scan localhost for adbd port
    connect <port>        Connect to explicit port and open shell

FILE OPERATIONS:
    cp <src> <dst>        Copy files between Termux and device (or device-to-device)
    mv <src> <dst>        Move/rename files (cross-boundary or device-internal)
    push <local> <remote> Upload file to device (/sdcard, /data/local/tmp)
    pull <remote> <local> Download file from device to Termux

APP & SYSTEM UTILITIES:
    install <file.apk>    Direct stream APK installation (pm install -r -d -t)
    screenshot [file.png] Capture screen directly to local image file (screencap -p)
    screenrecord <file>   Record screen video directly to file
    launch <package>      Launch app by package name (am start)
    stop <package>        Force-stop application (am force-stop)
    clear <package>       Clear application data and cache (pm clear)
    battery               Shortcut: Show battery service state (dumpsys battery)
    pm <args...>          Shortcut: Package manager commands (e.g. pm list packages -3)
"#
    );
}

fn resolve_port() -> u16 {
    match scan_local_adbd(30000, 45000) {
        Some(port) => port,
        None => {
            eprintln!(
                "[-] Could not automatically find open Wireless Debugging port on localhost."
            );
            eprintln!(
                "[-] Please ensure Wireless Debugging is enabled in Developer Options."
            );
            exit(1);
        }
    }
}

fn run_pair_flow(args: &[String]) {
    let (port, code) = if args.len() >= 2 {
        (args[0].clone(), args[1].clone())
    } else {
        println!(
            "[*] Opening Developer Options so you can tap 'Pair device with pairing code'..."
        );
        let _ = Command::new("am")
            .args([
                "start",
                "-a",
                "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
            ])
            .output();

        use std::io::{Write, stdin, stdout};
        let mut p = String::new();
        let mut c = String::new();

        print!("[?] Enter pairing port shown on screen: ");
        let _ = stdout().flush();
        stdin().read_line(&mut p).expect("Failed to read port");

        print!("[?] Enter 6-digit pairing code: ");
        let _ = stdout().flush();
        stdin().read_line(&mut c).expect("Failed to read code");

        (p.trim().to_string(), c.trim().to_string())
    };

    let target = if port.contains(':') {
        port
    } else {
        format!("127.0.0.1:{}", port)
    };

    println!(
        "[*] Native pure-Rust pairing with {} using code {}...",
        target, code
    );
    match crypto::pair_device(&target, &code, Duration::from_secs(5)) {
        Ok(()) => {
            println!("[+] Successfully paired natively without external adb!");
            println!("[+] ruri's RSA public key is now trusted by adbd.");
        }
        Err(e) => {
            eprintln!(
                "[-] Pairing failed: {}. Make sure the pairing dialog is still active on screen.",
                e
            );
            exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        let port = resolve_port();
        connect_and_shell(port);
        return;
    }

    match args[0].as_str() {
        "help" | "-h" | "--help" => {
            print_usage();
        }
        "run" => {
            if args.len() < 2 {
                eprintln!("Usage: ruri run <command> [args...]");
                exit(1);
            }
            let cmd = &args[1];
            let sub_args = &args[2..];
            let port = resolve_port();

            println!(
                "[*] Transparent VFS supervisor active for '{}' (adbd localhost:{})",
                cmd, port
            );
            let code = ruri_interceptor::supervisor::run_supervised_command(
                cmd,
                sub_args,
                move |_pid, path, _flags, _mode| {
                    if path.starts_with("/data/local/tmp/") || path.starts_with("/sdcard/") {
                        println!("[intercept:openat] Streaming remote file: {}", path);
                        let addr = format!("127.0.0.1:{}", port);
                        if let Ok(conn) = AdbConnection::connect(&addr, Duration::from_secs(3)) {
                            let stream = conn.into_stream();
                            let mut buf = Vec::new();
                            let exec_cmd = format!("cat '{}'", path);
                            if protocol::run_exec_to_writer(stream, &exec_cmd, &mut buf).is_ok() {
                                // Create anonymous in-memory file descriptor
                                let memfd_name = std::ffi::CString::new("ruri_vfs").unwrap();
                                let mfd = unsafe { libc::syscall(libc::SYS_memfd_create, memfd_name.as_ptr(), libc::MFD_CLOEXEC) } as i32;
                                if mfd >= 0 {
                                    use std::io::Write;
                                    use std::os::fd::FromRawFd;
                                    let mut f = unsafe { std::fs::File::from_raw_fd(mfd) };
                                    let _ = f.write_all(&buf);
                                    let _ = f.flush();
                                    unsafe { libc::lseek(mfd, 0, libc::SEEK_SET) };
                                    std::mem::forget(f); // keep fd open for injection
                                    return ruri_interceptor::supervisor::InterceptDecision::InjectFd(mfd);
                                }
                            }
                        }
                        ruri_interceptor::supervisor::InterceptDecision::ReturnError(libc::ENOENT)
                    } else {
                        ruri_interceptor::supervisor::InterceptDecision::ContinueNative
                    }
                },
            ).unwrap_or_else(|e| {
                eprintln!("[-] Supervised run error: {}", e);
                exit(1);
            });
            exit(code);
        }
        "pair" => {
            run_pair_flow(&args[1..]);
        }
        "scan" => {
            println!("[*] Scanning 127.0.0.1 (ports 30000..45000) for adbd...");
            let start = std::time::Instant::now();
            match scan_local_adbd(30000, 45000) {
                Some(port) => {
                    let elapsed = start.elapsed();
                    println!(
                        "[+] Found adbd on 127.0.0.1:{} (took {:.2?})",
                        port, elapsed
                    );
                }
                None => {
                    eprintln!(
                        "[-] No adbd found on localhost. Is Wireless Debugging on?"
                    );
                    exit(1);
                }
            }
        }
        "connect" => {
            if args.len() < 2 {
                eprintln!("Usage: ruri connect <port>");
                exit(1);
            }
            let port: u16 = args[1].parse().expect("Invalid port number");
            connect_and_shell(port);
        }
        "shell" => {
            let port = resolve_port();
            connect_and_shell(port);
        }
        "exec" => {
            if args.len() < 2 {
                eprintln!("Usage: ruri exec <command>");
                exit(1);
            }
            let cmd = args[1..].join(" ");
            let port = resolve_port();
            connect_and_exec(port, &cmd);
        }
        "screenshot" => {
            let out_file = if args.len() >= 2 {
                args[1].clone()
            } else {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                format!("screenshot_{}.png", timestamp)
            };
            println!("[*] Capturing screen to {}...", out_file);
            let port = resolve_port();
            let addr = format!("127.0.0.1:{}", port);
            match AdbConnection::connect(&addr, Duration::from_secs(3)) {
                Ok(conn) => {
                    let stream = conn.into_stream();
                    if let Err(e) =
                        run_exec_to_file(stream, "screencap -p", &out_file)
                    {
                        eprintln!("[-] Screenshot failed: {}", e);
                        exit(1);
                    }
                    println!("[+] Screenshot saved successfully to {}", out_file);
                }
                Err(e) => {
                    eprintln!("[-] Connection error: {}", e);
                    exit(1);
                }
            }
        }
        "install" => {
            if args.len() < 2 {
                eprintln!("Usage: ruri install <file.apk>");
                exit(1);
            }
            let apk_path = &args[1];
            if !Path::new(apk_path).exists() {
                eprintln!("[-] File not found: {}", apk_path);
                exit(1);
            }
            let file = File::open(apk_path).expect("Cannot open APK file");
            let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
            println!(
                "[*] Streaming {} ({:.2} MB) into pm install...",
                apk_path,
                file_size as f64 / 1_048_576.0
            );

            let port = resolve_port();
            let addr = format!("127.0.0.1:{}", port);
            let cmd = format!("pm install -r -d -t -S {}", file_size);
            match AdbConnection::connect(&addr, Duration::from_secs(3)) {
                Ok(conn) => {
                    let stream = conn.into_stream();
                    if let Err(e) = run_exec_piped_input(stream, &cmd, file) {
                        eprintln!("[-] Installation error: {}", e);
                        exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("[-] Connection error: {}", e);
                    exit(1);
                }
            }
        }
        "cp" => {
            if args.len() < 3 {
                eprintln!("Usage: ruri cp <src> <dst>");
                eprintln!(
                    "Prefix with ':' to explicitly force adbd remote (e.g. ruri cp :file.txt local.txt)"
                );
                exit(1);
            }
            let (src_is_remote, clean_src) = if args[1].starts_with(':') {
                (true, &args[1][1..])
            } else if args[1].starts_with("/data/local/tmp")
                || args[1].starts_with("/sdcard")
                || args[1].starts_with("/system")
            {
                (true, args[1].as_str())
            } else {
                (!Path::new(&args[1]).exists(), args[1].as_str())
            };

            let (dst_is_remote, clean_dst) = if args[2].starts_with(':') {
                (true, &args[2][1..])
            } else if args[2].starts_with("/data/local/tmp")
                || args[2].starts_with("/sdcard")
                || args[2].starts_with("/system")
            {
                (true, args[2].as_str())
            } else {
                (false, args[2].as_str())
            };

            let port = resolve_port();

            if !src_is_remote && dst_is_remote {
                // Local -> Remote (push)
                let addr = format!("127.0.0.1:{}", port);
                let conn = AdbConnection::connect(&addr, Duration::from_secs(3))
                    .map_err(|e| {
                        eprintln!("[-] Connection error: {}", e);
                        exit(1);
                    })
                    .unwrap();
                let stream = conn.into_stream();
                if let Err(e) = push_file(stream, Path::new(clean_src), clean_dst) {
                    eprintln!("[-] Copy failed: {}", e);
                    exit(1);
                }
                println!("[+] Copied {} -> [adbd]{}", clean_src, clean_dst);
            } else if src_is_remote && !dst_is_remote {
                // Remote -> Local (pull)
                let addr = format!("127.0.0.1:{}", port);
                let conn = AdbConnection::connect(&addr, Duration::from_secs(3))
                    .map_err(|e| {
                        eprintln!("[-] Connection error: {}", e);
                        exit(1);
                    })
                    .unwrap();
                let stream = conn.into_stream();
                if let Err(e) = pull_file(stream, clean_src, Path::new(clean_dst)) {
                    eprintln!("[-] Copy failed: {}", e);
                    exit(1);
                }
                println!("[+] Copied [adbd]{} -> {}", clean_src, clean_dst);
            } else if src_is_remote && dst_is_remote {
                // Remote -> Remote
                let cmd = format!("cp -r '{}' '{}'", clean_src, clean_dst);
                connect_and_exec(port, &cmd);
                println!("[+] Copied [adbd]{} -> [adbd]{}", clean_src, clean_dst);
            } else {
                // Local -> Local
                match std::fs::copy(clean_src, clean_dst) {
                    Ok(n) => println!("[+] Copied {} bytes (local -> local)", n),
                    Err(e) => {
                        eprintln!("[-] Copy error: {}", e);
                        exit(1);
                    }
                }
            }
        }
        "mv" => {
            if args.len() < 3 {
                eprintln!("Usage: ruri mv <src> <dst>");
                eprintln!(
                    "Prefix with ':' to explicitly force adbd remote (e.g. ruri mv :file.txt local.txt)"
                );
                exit(1);
            }
            let (src_is_remote, clean_src) = if args[1].starts_with(':') {
                (true, &args[1][1..])
            } else if args[1].starts_with("/data/local/tmp")
                || args[1].starts_with("/sdcard")
                || args[1].starts_with("/system")
            {
                (true, args[1].as_str())
            } else {
                (!Path::new(&args[1]).exists(), args[1].as_str())
            };

            let (dst_is_remote, clean_dst) = if args[2].starts_with(':') {
                (true, &args[2][1..])
            } else if args[2].starts_with("/data/local/tmp")
                || args[2].starts_with("/sdcard")
                || args[2].starts_with("/system")
            {
                (true, args[2].as_str())
            } else {
                (false, args[2].as_str())
            };

            let port = resolve_port();

            if !src_is_remote && dst_is_remote {
                // Local -> Remote (push + rm local)
                let addr = format!("127.0.0.1:{}", port);
                let conn = AdbConnection::connect(&addr, Duration::from_secs(3))
                    .map_err(|e| {
                        eprintln!("[-] Connection error: {}", e);
                        exit(1);
                    })
                    .unwrap();
                let stream = conn.into_stream();
                if let Err(e) = push_file(stream, Path::new(clean_src), clean_dst) {
                    eprintln!("[-] Move failed: {}", e);
                    exit(1);
                }
                let _ = std::fs::remove_file(clean_src);
                println!("[+] Moved {} -> [adbd]{}", clean_src, clean_dst);
            } else if src_is_remote && !dst_is_remote {
                // Remote -> Local (pull + rm remote)
                let addr = format!("127.0.0.1:{}", port);
                let conn = AdbConnection::connect(&addr, Duration::from_secs(3))
                    .map_err(|e| {
                        eprintln!("[-] Connection error: {}", e);
                        exit(1);
                    })
                    .unwrap();
                let stream = conn.into_stream();
                if let Err(e) = pull_file(stream, clean_src, Path::new(clean_dst)) {
                    eprintln!("[-] Move failed: {}", e);
                    exit(1);
                }
                let rm_cmd = format!("rm -rf '{}'", clean_src);
                connect_and_exec(port, &rm_cmd);
                println!("[+] Moved [adbd]{} -> {}", clean_src, clean_dst);
            } else if src_is_remote && dst_is_remote {
                // Remote -> Remote
                let cmd = format!("mv '{}' '{}'", clean_src, clean_dst);
                connect_and_exec(port, &cmd);
                println!("[+] Moved [adbd]{} -> [adbd]{}", clean_src, clean_dst);
            } else {
                // Local -> Local
                match std::fs::rename(clean_src, clean_dst) {
                    Ok(_) => println!("[+] Moved {} -> {}", clean_src, clean_dst),
                    Err(e) => {
                        eprintln!("[-] Move error: {}", e);
                        exit(1);
                    }
                }
            }
        }
        "push" => {
            if args.len() < 3 {
                eprintln!("Usage: ruri push <local_file> <remote_destination>");
                exit(1);
            }
            let local_path = Path::new(&args[1]);
            let remote_path = &args[2];
            if !local_path.exists() {
                eprintln!("[-] Local file does not exist: {}", local_path.display());
                exit(1);
            }
            let port = resolve_port();
            let addr = format!("127.0.0.1:{}", port);
            match AdbConnection::connect(&addr, Duration::from_secs(3)) {
                Ok(conn) => {
                    let stream = conn.into_stream();
                    if let Err(e) = push_file(stream, local_path, remote_path) {
                        eprintln!("[-] Push failed: {}", e);
                        exit(1);
                    }
                    println!(
                        "[+] Successfully pushed {} to {}",
                        local_path.display(),
                        remote_path
                    );
                }
                Err(e) => {
                    eprintln!("[-] Connection error: {}", e);
                    exit(1);
                }
            }
        }
        "pull" => {
            if args.len() < 3 {
                eprintln!("Usage: ruri pull <remote_file> <local_destination>");
                exit(1);
            }
            let remote_path = &args[1];
            let local_path = Path::new(&args[2]);
            let port = resolve_port();
            let addr = format!("127.0.0.1:{}", port);
            match AdbConnection::connect(&addr, Duration::from_secs(3)) {
                Ok(conn) => {
                    let stream = conn.into_stream();
                    if let Err(e) = pull_file(stream, remote_path, local_path) {
                        eprintln!("[-] Pull failed: {}", e);
                        exit(1);
                    }
                    println!(
                        "[+] Successfully pulled {} to {}",
                        remote_path,
                        local_path.display()
                    );
                }
                Err(e) => {
                    eprintln!("[-] Connection error: {}", e);
                    exit(1);
                }
            }
        }
        "launch" => {
            if args.len() < 2 {
                eprintln!("Usage: ruri launch <package_name>");
                exit(1);
            }
            let pkg = &args[1];
            let port = resolve_port();
            let cmd =
                format!("monkey -p {} -c android.intent.category.LAUNCHER 1", pkg);
            connect_and_exec(port, &cmd);
        }
        "stop" => {
            if args.len() < 2 {
                eprintln!("Usage: ruri stop <package_name>");
                exit(1);
            }
            let pkg = &args[1];
            let port = resolve_port();
            let cmd = format!("am force-stop {}", pkg);
            connect_and_exec(port, &cmd);
            println!("[+] Stopped {}", pkg);
        }
        "clear" => {
            if args.len() < 2 {
                eprintln!("Usage: ruri clear <package_name>");
                exit(1);
            }
            let pkg = &args[1];
            let port = resolve_port();
            let cmd = format!("pm clear {}", pkg);
            connect_and_exec(port, &cmd);
        }
        "battery" => {
            let port = resolve_port();
            connect_and_exec(port, "dumpsys battery");
        }
        "pm" => {
            let port = resolve_port();
            let cmd = format!("pm {}", args[1..].join(" "));
            connect_and_exec(port, &cmd);
        }
        _other => {
            let cmd = args.join(" ");
            let port = resolve_port();
            connect_and_exec(port, &cmd);
        }
    }
}

fn connect_and_shell(port: u16) {
    let addr = format!("127.0.0.1:{}", port);
    match AdbConnection::connect(&addr, Duration::from_secs(3)) {
        Ok(conn) => {
            let stream = conn.into_stream();
            if let Err(e) = run_interactive_shell(stream) {
                eprintln!("[-] Shell error: {}", e);
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("[-] Failed to connect to {}: {}", addr, e);
            exit(1);
        }
    }
}

fn connect_and_exec(port: u16, cmd: &str) {
    let addr = format!("127.0.0.1:{}", port);
    match AdbConnection::connect(&addr, Duration::from_secs(3)) {
        Ok(conn) => {
            let stream = conn.into_stream();
            if let Err(e) = run_exec_command(stream, cmd) {
                eprintln!("[-] Exec error: {}", e);
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("[-] Failed to connect to {}: {}", addr, e);
            exit(1);
        }
    }
}
