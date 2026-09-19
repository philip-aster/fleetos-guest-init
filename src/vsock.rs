// SPDX-License-Identifier: Apache-2.0
//! Blocking AF_VSOCK I/O. No async runtime.

use crate::error::GuestInitError;
use crate::protocol::{HOST_CID, VSOCK_PORT};

const AF_VSOCK: libc::c_int = 40;

/// `struct sockaddr_vm` (linux/vm_sockets.h).
#[repr(C)]
struct SockaddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

/// Open a blocking AF_VSOCK stream connection to the host agent.
pub fn connect() -> Result<i32, GuestInitError> {
    unsafe {
        let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(GuestInitError::Vsock(format!(
                "socket(AF_VSOCK) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut addr: SockaddrVm = std::mem::zeroed();
        addr.svm_family = AF_VSOCK as u16;
        addr.svm_port = VSOCK_PORT;
        addr.svm_cid = HOST_CID;
        let ret = libc::connect(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        );
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(GuestInitError::Vsock(format!("connect() failed: {}", err)));
        }
        Ok(fd)
    }
}

pub fn read_exact(fd: i32, buf: &mut [u8]) -> Result<(), GuestInitError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = unsafe {
            libc::read(
                fd,
                buf[filled..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - filled,
            )
        };
        if n < 0 {
            return Err(GuestInitError::Io(std::io::Error::last_os_error()));
        }
        if n == 0 {
            return Err(GuestInitError::Vsock("unexpected EOF".into()));
        }
        filled += n as usize;
    }
    Ok(())
}

pub fn write_all(fd: i32, buf: &[u8]) -> Result<(), GuestInitError> {
    let mut written = 0usize;
    while written < buf.len() {
        let n = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr() as *const libc::c_void,
                buf.len() - written,
            )
        };
        if n < 0 {
            return Err(GuestInitError::Io(std::io::Error::last_os_error()));
        }
        written += n as usize;
    }
    Ok(())
}

pub fn close(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}
