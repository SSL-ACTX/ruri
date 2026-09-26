use std::io::{self};
use std::os::fd::AsRawFd;

pub struct RawTerminal {
    original_termios: Option<libc::termios>,
    fd: i32,
}

impl RawTerminal {
    pub fn new() -> io::Result<Self> {
        let fd = io::stdin().as_raw_fd();
        let is_atty = unsafe { libc::isatty(fd) } == 1;

        if !is_atty {
            return Ok(Self {
                original_termios: None,
                fd,
            });
        }

        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let original = termios;

        // Set raw mode
        unsafe {
            libc::cfmakeraw(&mut termios);
            if libc::tcsetattr(fd, libc::TCSANOW, &termios) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Self {
            original_termios: Some(original),
            fd,
        })
    }

    pub fn get_window_size() -> (u16, u16) {
        // (rows, cols)
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let fd = io::stdout().as_raw_fd();
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 {
            (ws.ws_row, ws.ws_col)
        } else {
            (24, 80)
        }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        if let Some(ref orig) = self.original_termios {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, orig);
            }
        }
    }
}
