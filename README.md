# Ruri
 
**A Lightweight Pure-Rust Wireless ADB Client and Engine**
 
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Android_%7C_Linux-green.svg)]()
 
> [!NOTE]
> `ruri` is an independent, zero-dependency pure-Rust implementation of the Android Debug Bridge (ADB) protocol. It runs natively on-device (e.g. inside Termux on Android) and Linux without requiring Google's official `adb` binary, Android SDK tools, or background server daemons.
 
---
 
## Overview
 
Traditional ADB setups on Android devices require either rooting the device, running a bulky multi-megabyte C/C++ `adb` client bundled with a separate server daemon, or routing through Shizuku's IPC binder service (`rish`).
 
`ruri` implements the core ADB framing protocol, SPAKE2 TLS pairing engine, sync file transfer, and pseudo-terminal (PTY) handling in pure Rust. It connects directly to the local `adbd` wireless debugging socket over `127.0.0.1`, authenticates via RSA / TLS certificates, and grants UID 2000 (`shell`) privileges with near-zero latency and minimal memory overhead.

Beyond standard ADB operations, `ruri` includes a dedicated kernel syscall interceptor crate (`ruri-interceptor`). Utilizing `seccomp-bpf` user notifications and macro-driven ARM64 syscall dispatch, it enables user-space POSIX filesystem virtualization—intercepting `openat` and file operations transparently to bridge Termux userland with privileged Android namespaces (`/data/local/tmp`, `/sdcard`) without requiring `/dev/fuse` or root privileges.
 
---
 
## Architecture
 
```mermaid
graph TD
    User["Terminal / User / Script"] --> CLI["ruri CLI / Crate API"]

    subgraph "ruri Workspace"
        CLI --> RuriInterceptor["crates/ruri-interceptor (seccomp-bpf / Macro Syscall Table)"]
        CLI --> Scanner["Port Scanner (/proc/net/tcp)"]
        CLI --> Pair["SPAKE2 Pairing Engine (TLS 1.3 / Ed25519)"]
        CLI --> Transport["TCP Transport Layer"]

        Transport --> Protocol["ADB Framing (CNXN / AUTH / OPEN / WRTE)"]
        Protocol --> Sync["Sync Engine (SEND / RECV / DATA)"]
        Protocol --> PTY["PTY Shell & Raw Terminal Handler"]
    end

    subgraph "Target Device (Localhost)"
        RuriInterceptor -. "Intercept Syscalls / Inject FDs" .-> ChildProc["Supervised Process"]
        Scanner -. "Detect Port" .-> ADBD["Android adbd (UID 2000)"]
        Pair -- "TLS Handshake + Code" --> ADBD
        Protocol -- "Direct TCP Stream" --> ADBD
    end
```
 
---
 
## Features
 
- **Native Protocol Implementation**: Directly handles ADB packet framing (`A_CNXN`, `A_AUTH`, `A_OPEN`, `A_OKAY`, `A_WRTE`, `A_CLSE`) over raw TCP sockets.
- **Pure-Rust Wireless Pairing**: Full native AOSP SPAKE2 implementation over TLS 1.3 key material export (RFC 5705) and Curve25519/Ed25519 scalar arithmetic, pairing directly with Android 11+ `adbd` with zero external dependencies.
- **Zero-Config Port Scanning**: Automatically identifies the ephemeral wireless debugging port assigned by Android via `/proc/net/tcp6` and `/proc/net/tcp` inspection, with fallback caching in `~/.ruri/last_port`.
- **Interactive PTY Shell**: Configures host terminal into raw mode (`termios`) with non-blocking asynchronous standard I/O polling, supporting full escape codes, signals, and text editors (`nano`, `vi`).
- **Cross-Boundary File Operations**: Moves (`mv`) and copies (`cp`) files across Termux and Android device internal storage (`/data/local/tmp`, `/sdcard`) via native streaming sync.
- **Direct Stream Transfers**: Implements the ADB `sync:` subprotocol (`SEND`, `RECV`, `DATA`, `DONE`) for file push and pull operations without base64 or temporary disk staging.
- **Dual Target Distribution**: Compiles to a standalone binary (`ruri`), a Rust library crate (`rlib`), and a C-compatible shared library (`libruri.so`).
 
---
 
## CLI Usage
 
### Initial Setup & Pairing (One-Time)
 
Enable **Wireless Debugging** in Developer Options, tap **Pair device with pairing code**, and run:
 
```bash
# Interactive mode (prompts for port and 6-digit code):
ruri pair

# Or provide them directly:
ruri pair <port> <code>
```
 
Once paired, the key is permanently authorized. Subsequent executions auto-detect the active debugging port.
 
### Core Commands
 
```bash
# Open interactive shell (UID 2000)
ruri shell

# Execute a non-interactive command and stream output
ruri exec "pm list packages -3"

# Connect to an explicit port
ruri connect 38451

# Scan localhost for open adbd instance
ruri scan
```
 
### Cross-Boundary File Operations
 
```bash
# Copy file between Termux and device namespaces
ruri cp ./local_config.json /data/local/tmp/config.json
ruri cp /data/local/tmp/config.json ./downloaded_config.json

# Move file across boundaries (transfers then deletes source)
ruri mv ./payload.bin /data/local/tmp/payload.bin
ruri mv /data/local/tmp/payload.bin ./restored.bin

# Direct push and pull
ruri push ./payload.bin /data/local/tmp/payload.bin
ruri pull /sdcard/Download/test.log ./test.log
```
 
### App & System Utilities
 
```bash
# Direct stream APK installation (pm install -r -d -t)
ruri install app-release.apk

# Capture screenshot directly to image file
ruri screenshot display.png

# Record screen video directly to file
ruri screenrecord screen.mp4

# App process management
ruri launch com.example.app
ruri stop com.example.app
ruri clear com.example.app

# Quick shortcuts
ruri battery
ruri pm list packages -s
```
 
---
 
## Programmatic Usage
 
### Rust Crate
 
Add `ruri` to your `Cargo.toml`:
 
```rust
use ruri::RuriClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Auto-detect port on localhost
    let client = RuriClient::auto_connect()?;

    // Execute command and capture output
    let output = client.exec("id")?;
    println!("Device response: {}", output);

    // Push file
    client.push_file("local.txt", "/data/local/tmp/remote.txt")?;

    Ok(())
}
```
 
### C-ABI / FFI (`libruri.so`)
 
`ruri` exports C-compatible symbols for embedding into other languages:
 
```c
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char* data;
    uintptr_t len;
    bool success;
} RuriResult;

uint16_t ruri_scan_port(void);
RuriResult ruri_exec_cmd(const char* cmd);
void ruri_free_result(RuriResult res);
```
 
---
 
## Building from Source
 
```bash
# Debug build (fast compilation)
cargo build

# Optimized release binary
cargo build --release

# Run workspace unit and kernel integration tests
cargo test
```

### Artifacts & Targets

The build process outputs the standalone executable and dynamic library to `target/`:

- **CLI Binary**: `target/release/ruri` (or `target/debug/ruri`)
- **C-ABI Shared Library**: `target/release/libruri.so` (or `target/debug/libruri.so`)
- **Rust Library Crate**: `crates/ruri` & `crates/ruri-interceptor` (importable directly in Cargo.toml)
 
---
 
## License
 
Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
 
---
 
<div align="center">
 
Built with 🦀 by [Seuriin](https://github.com/SSL-ACTX) and [Iris-Seravelle](https://github.com/Iris-Seravelle)
 
</div>
