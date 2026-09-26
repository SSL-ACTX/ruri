//! seccomp-bpf user-notification interceptor engine for ARM64 Linux / Android.

use std::io;

pub const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 8;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_int = 0xc0502100u32 as i32;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_int = 0xc0182101u32 as i32;
pub const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_int = 0x40182103u32 as i32;
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 0x00000001;
pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 0x00000001;
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 0x00000002;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

// BPF instruction helpers
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_DATA_NR_OFFSET: u32 = 0;

/// Installs a seccomp user-notif filter for a target syscall number.
/// Returns the listener file descriptor (`notif_fd`).
pub fn install_user_notif_filter(target_sysno: i64) -> io::Result<i32> {
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let filter: [SockFilter; 4] = [
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: target_sysno as u32,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_USER_NOTIF,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const SockFprog,
        )
    };

    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd as i32)
    }
}

/// Receives an interception notification from the kernel.
pub fn recv_notification(notif_fd: i32) -> io::Result<SeccompNotif> {
    let mut req: SeccompNotif = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut req) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(req)
    }
}

/// Responds to the kernel with a return value or tells it to continue natively.
pub fn respond_notification(
    notif_fd: i32,
    id: u64,
    val: i64,
    err: i32,
    continue_sys: bool,
) -> io::Result<()> {
    let mut resp = SeccompNotifResp {
        id,
        val,
        error: err,
        flags: if continue_sys {
            SECCOMP_USER_NOTIF_FLAG_CONTINUE
        } else {
            0
        },
    };
    let ret = unsafe { libc::ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &mut resp) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Injects a file descriptor directly into the intercepted target process at the syscall.
pub fn inject_fd(
    notif_fd: i32,
    id: u64,
    local_fd: i32,
    close_on_exec: bool,
) -> io::Result<i32> {
    let mut addfd = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: local_fd as u32,
        newfd: 0,
        newfd_flags: if close_on_exec {
            libc::O_CLOEXEC as u32
        } else {
            0
        },
    };
    let ret =
        unsafe { libc::ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &mut addfd) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as i32)
    }
}
