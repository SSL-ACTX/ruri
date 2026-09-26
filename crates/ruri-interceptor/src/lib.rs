pub mod seccomp;
pub mod supervisor;
pub mod table;

#[macro_use]
mod macros {
    macro_rules! define_syscall_enum {
        ($(($variant:ident, $num:expr, $name:expr),)*) => {
            /// ARM64 Linux Syscall Number
            #[repr(i64)]
            #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub enum Sysno {
                $($variant = $num,)*
                Unknown(i64),
            }

            impl Sysno {
                /// Converts raw syscall number to typed `Sysno`
                #[inline]
                pub const fn from_raw(num: i64) -> Self {
                    match num {
                        $($num => Sysno::$variant,)*
                        other => Sysno::Unknown(other),
                    }
                }

                /// Returns raw syscall number
                #[inline]
                pub const fn to_raw(self) -> i64 {
                    match self {
                        $(Sysno::$variant => $num,)*
                        Sysno::Unknown(other) => other,
                    }
                }

                /// Returns standard Linux syscall name
                #[inline]
                pub const fn name(self) -> &'static str {
                    match self {
                        $(Sysno::$variant => $name,)*
                        Sysno::Unknown(_) => "unknown",
                    }
                }

                /// Returns true if this is a filesystem-related syscall
                #[inline]
                pub const fn is_fs(&self) -> bool {
                    matches!(
                        self,
                        Sysno::Openat
                            | Sysno::Openat2
                            | Sysno::Close
                            | Sysno::Read
                            | Sysno::Write
                            | Sysno::Readv
                            | Sysno::Writev
                            | Sysno::Pread64
                            | Sysno::Pwrite64
                            | Sysno::Preadv
                            | Sysno::Pwritev
                            | Sysno::Preadv2
                            | Sysno::Pwritev2
                            | Sysno::Lseek
                            | Sysno::Getdents64
                            | Sysno::Statx
                            | Sysno::Faccessat
                            | Sysno::Faccessat2
                            | Sysno::Fchmod
                            | Sysno::Fchmodat
                            | Sysno::Fchown
                            | Sysno::Fchownat
                            | Sysno::Mkdirat
                            | Sysno::Mknodat
                            | Sysno::Unlinkat
                            | Sysno::Renameat
                            | Sysno::Renameat2
                            | Sysno::Readlinkat
                            | Sysno::Symlinkat
                            | Sysno::Linkat
                            | Sysno::Fallocate
                    )
                }
            }

            impl core::fmt::Display for Sysno {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    match self {
                        Sysno::Unknown(n) => write!(f, "sys_unknown({})", n),
                        other => write!(f, "sys_{}", other.name()),
                    }
                }
            }
        };
    }

    crate::for_each_aarch64_syscall!(define_syscall_enum);
}

pub use macros::Sysno;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm64_syscall_macro_mapping() {
        assert_eq!(Sysno::from_raw(56), Sysno::Openat);
        assert_eq!(Sysno::Openat.to_raw(), 56);
        assert_eq!(Sysno::Openat.name(), "openat");
        assert!(Sysno::Openat.is_fs());

        assert_eq!(Sysno::from_raw(64), Sysno::Write);
        assert_eq!(Sysno::from_raw(220), Sysno::Clone);
        assert_eq!(Sysno::from_raw(291), Sysno::Statx);
        assert!(Sysno::Statx.is_fs());
        assert_eq!(Sysno::from_raw(438), Sysno::PidfdGetfd);
        assert_eq!(Sysno::PidfdGetfd.name(), "pidfd_getfd");

        // Display
        assert_eq!(format!("{}", Sysno::Openat), "sys_openat");
        assert_eq!(format!("{}", Sysno::from_raw(9999)), "sys_unknown(9999)");
    }

    #[test]
    fn test_live_syscall_interception_and_response() {
        use std::thread;

        // Install filter for Sysno::Statx (291)
        let notif_fd = match seccomp::install_user_notif_filter(
            Sysno::Statx.to_raw(),
        ) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!(
                    "Skipping live intercept test (no seccomp listener privs): {:?}",
                    e
                );
                return;
            }
        };

        // Spawn child thread to trigger Statx syscall
        let handle = thread::spawn(move || {
            // Give parent time to wait on ioctl
            std::thread::sleep(std::time::Duration::from_millis(50));
            let path = std::ffi::CString::new("/").unwrap();
            let mut statx_buf: [u8; 256] = [0u8; 256];
            unsafe {
                libc::syscall(
                    libc::SYS_statx,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    0,
                    0,
                    statx_buf.as_mut_ptr(),
                )
            };
        });

        // Supervisor receives notification
        let notif =
            seccomp::recv_notification(notif_fd).expect("recv_notification failed");
        assert_eq!(notif.data.nr, Sysno::Statx.to_raw() as i32);

        // Supervisor responds telling kernel to continue execution
        seccomp::respond_notification(notif_fd, notif.id, 0, 0, true)
            .expect("respond_notification failed");

        handle.join().unwrap();
        unsafe { libc::close(notif_fd) };
    }
}
