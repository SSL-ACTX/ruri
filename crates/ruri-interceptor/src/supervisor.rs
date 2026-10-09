use crate::seccomp::*;
use std::io;
use std::process::Command;

/// Reads a null-terminated C string from target PID's memory using process_vm_readv
pub fn read_target_string(
    pid: u32,
    remote_addr: u64,
    max_len: usize,
) -> io::Result<String> {
    let mut buf = vec![0u8; max_len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: max_len,
    };
    let remote_iov = libc::iovec {
        iov_base: remote_addr as *mut libc::c_void,
        iov_len: max_len,
    };

    let ret = unsafe {
        libc::process_vm_readv(
            pid as libc::pid_t,
            &local_iov as *const libc::iovec,
            1,
            &remote_iov as *const libc::iovec,
            1,
            0,
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let n = ret as usize;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Ok(String::from_utf8_lossy(&buf[..end]).to_string())
}

pub enum InterceptDecision {
    ContinueNative,
    InjectFd(i32),
    ReturnError(i32),
}

/// Runs a command under the seccomp supervisor, intercepting filesystem syscalls.
pub fn run_supervised_command<F>(
    cmd: &str,
    args: &[String],
    on_openat: F,
) -> io::Result<i32>
where
    F: Fn(u32, &str, i32, u32) -> InterceptDecision + Send + 'static,
{
    use std::os::unix::process::CommandExt;

    // Create a UNIX socketpair to pass the listener file descriptor using SCM_RIGHTS
    let mut sv = [-1i32; 2];
    if unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr())
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let (parent_sock, child_sock) = (sv[0], sv[1]);

    let mut command = Command::new(cmd);
    command.args(args);

    unsafe {
        command.pre_exec(move || {
            libc::close(parent_sock);

            // Install seccomp user-notif filter on child before exec
            match install_user_notif_filter(56) {
                Ok(notif_fd) => {
                    // Send notif_fd across UNIX domain socket via SCM_RIGHTS
                    let mut iov = libc::iovec {
                        iov_base: b"OK".as_ptr() as *mut libc::c_void,
                        iov_len: 2,
                    };

                    #[repr(C)]
                    union CmsgBuf {
                        hdr: libc::cmsghdr,
                        buf: [u8; unsafe {
                            libc::CMSG_SPACE(
                                std::mem::size_of::<libc::c_int>() as u32
                            ) as usize
                        }],
                    }
                    let mut cmsg_union: CmsgBuf = std::mem::zeroed();

                    let mut msg: libc::msghdr = std::mem::zeroed();
                    msg.msg_iov = &mut iov;
                    msg.msg_iovlen = 1;
                    msg.msg_control = &mut cmsg_union as *mut _ as *mut libc::c_void;
                    msg.msg_controllen = std::mem::size_of_val(&cmsg_union) as usize;

                    let cmsg = libc::CMSG_FIRSTHDR(&msg);
                    (*cmsg).cmsg_level = libc::SOL_SOCKET;
                    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                    (*cmsg).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32)
                            as usize;

                    let fd_ptr = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
                    *fd_ptr = notif_fd;

                    libc::sendmsg(child_sock, &msg, 0);
                    libc::close(notif_fd);
                    libc::close(child_sock);
                    Ok(())
                }
                Err(e) => {
                    libc::close(child_sock);
                    Err(e)
                }
            }
        });
    }

    let mut child = command.spawn()?;
    unsafe { libc::close(child_sock) };

    // Receive notif_fd from UNIX domain socket
    let notif_fd = unsafe {
        let mut dummy = [0u8; 2];
        let mut iov = libc::iovec {
            iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
            iov_len: dummy.len(),
        };

        #[repr(C)]
        union CmsgBuf {
            hdr: libc::cmsghdr,
            buf: [u8; unsafe {
                libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize
            }],
        }
        let mut cmsg_union: CmsgBuf = std::mem::zeroed();

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = &mut cmsg_union as *mut _ as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&cmsg_union) as usize;

        let ret = libc::recvmsg(parent_sock, &mut msg, 0);
        libc::close(parent_sock);

        if ret <= 0 {
            let _ = child.kill();
            return Err(io::Error::other("Failed to receive fd from child socket"));
        }

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            let _ = child.kill();
            return Err(io::Error::other("Invalid SCM_RIGHTS message received"));
        }

        let fd_ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
        *fd_ptr
    };

    let _child_pid = child.id();

    // Supervisor loop with non-blocking poll
    let mut pollfd = libc::pollfd {
        fd: notif_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    loop {
        // Poll for 50ms
        let poll_ret = unsafe { libc::poll(&mut pollfd, 1, 50) };
        if poll_ret > 0 && (pollfd.revents & libc::POLLIN) != 0 {
            while let Ok(notif) = recv_notification(notif_fd) {
                if notif.data.nr == 56 {
                    let path_addr = notif.data.args[1];
                    let flags = notif.data.args[2] as i32;
                    let mode = notif.data.args[3] as u32;

                    let path_str = read_target_string(notif.pid, path_addr, 4096)
                        .unwrap_or_default();

                    let decision = on_openat(notif.pid, &path_str, flags, mode);
                    match decision {
                        InterceptDecision::ContinueNative => {
                            if let Err(e) =
                                respond_notification(notif_fd, notif.id, 0, 0, true)
                            {
                                eprintln!(
                                    "[-] respond_notification (continue) failed: {}",
                                    e
                                );
                            }
                        }
                        InterceptDecision::InjectFd(local_fd) => {
                            if let Err(e) =
                                inject_fd(notif_fd, notif.id, local_fd, false)
                            {
                                eprintln!("[-] inject_fd failed: {}", e);
                            }
                            unsafe { libc::close(local_fd) };
                        }
                        InterceptDecision::ReturnError(err_no) => {
                            if let Err(e) = respond_notification(
                                notif_fd, notif.id, -1, err_no, false,
                            ) {
                                eprintln!(
                                    "[-] respond_notification (error) failed: {}",
                                    e
                                );
                            }
                        }
                    }
                } else {
                    let _ = respond_notification(notif_fd, notif.id, 0, 0, true);
                }
            }
        }

        // Check if child has finished
        match child.try_wait() {
            Ok(Some(status)) => {
                unsafe { libc::close(notif_fd) };
                return Ok(status.code().unwrap_or(0));
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }

    let status = child.wait()?;
    unsafe { libc::close(notif_fd) };
    Ok(status.code().unwrap_or(0))
}
