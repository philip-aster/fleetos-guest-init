// SPDX-License-Identifier: Apache-2.0
//! Network bring-up: loopback + eth0, addressing, default route.
//!
//! Called ONLY after attestation + config push, enforcing the boot-race
//! invariant (host agent must have armed eBPF policy before the guest NIC
//! goes live).

use std::ffi::CString;

use crate::error::GuestInitError;
use crate::protocol::WorkloadConfig;

// Linux ioctl request numbers.
const SIOCADDRT: libc::c_ulong = 0x890B;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const SIOCSIFADDR: libc::c_ulong = 0x8916;
const SIOCSIFNETMASK: libc::c_ulong = 0x891C;

const IFF_UP: i16 = 0x1;
const RTF_UP: i16 = 0x1;
const RTF_GATEWAY: i16 = 0x2;

/// `struct ifreq` — name + 16-byte union (flags / sockaddr).
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_ifru: [u8; 16],
}

/// `struct rtentry` (include/uapi/linux/route.h). Layout MUST match the kernel;
/// verify on a real MicroVM before relying on the default route.
#[repr(C)]
struct RtEntry {
    rt_pad1: libc::c_ulong,
    rt_dst: libc::sockaddr,
    rt_gateway: libc::sockaddr,
    rt_genmask: libc::sockaddr,
    rt_flags: libc::c_short,
    rt_refcnt: libc::c_short,
    rt_use: libc::c_ulong,
    rt_ifp: *mut libc::c_void,
    rt_metric: libc::c_short,
    rt_dev: *mut libc::c_char,
    rt_mss: libc::c_ulong,
    rt_window: libc::c_ulong,
    rt_irtt: libc::c_ushort,
}

pub fn bring_up(config: &WorkloadConfig) -> Result<(), GuestInitError> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(GuestInitError::Network(format!(
            "socket(AF_INET) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let result = configure(fd, config);
    unsafe {
        libc::close(fd);
    }
    result
}

fn configure(fd: i32, config: &WorkloadConfig) -> Result<(), GuestInitError> {
    // Loopback.
    set_addr(fd, "lo", [127, 0, 0, 1], SIOCSIFADDR)?;
    set_up(fd, "lo")?;

    // eth0.
    if config.guest_ip != [0, 0, 0, 0] {
        set_addr(fd, "eth0", config.guest_ip, SIOCSIFADDR)?;
        set_addr(fd, "eth0", config.netmask, SIOCSIFNETMASK)?;
    }
    set_up(fd, "eth0")?;

    if config.gateway != [0, 0, 0, 0] {
        if let Err(e) = add_default_route(fd, config.gateway, "eth0") {
            // Non-fatal: the interface is up; routing can be repaired by the
            // agent. Logged loudly so it is visible in the boot log.
            eprintln!("[fleetos-guest-init] WARNING: default route failed: {}", e);
        }
    }
    Ok(())
}

fn make_ifreq(name: &str) -> Result<IfReq, GuestInitError> {
    if name.len() >= libc::IFNAMSIZ {
        return Err(GuestInitError::Network("interface name too long".into()));
    }
    let mut ifr: IfReq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    Ok(ifr)
}

fn set_up(fd: i32, name: &str) -> Result<(), GuestInitError> {
    let mut ifr = make_ifreq(name)?;
    let ret = unsafe { libc::ioctl(fd, SIOCGIFFLAGS, &mut ifr as *mut IfReq) };
    if ret < 0 {
        return Err(GuestInitError::Network(format!(
            "SIOCGIFFLAGS({}) failed: {}",
            name,
            std::io::Error::last_os_error()
        )));
    }
    let flags = i16::from_ne_bytes([ifr.ifr_ifru[0], ifr.ifr_ifru[1]]);
    let new_flags = flags | IFF_UP;
    ifr.ifr_ifru[0..2].copy_from_slice(&new_flags.to_ne_bytes());
    let ret = unsafe { libc::ioctl(fd, SIOCSIFFLAGS, &mut ifr as *mut IfReq) };
    if ret < 0 {
        return Err(GuestInitError::Network(format!(
            "SIOCSIFFLAGS({}) failed: {}",
            name,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn set_addr(
    fd: i32,
    name: &str,
    ip: [u8; 4],
    request: libc::c_ulong,
) -> Result<(), GuestInitError> {
    let mut ifr = make_ifreq(name)?;
    let sin = sockaddr_in_from_ip(ip);
    let sin_bytes = unsafe {
        std::slice::from_raw_parts(
            &sin as *const libc::sockaddr_in as *const u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        )
    };
    ifr.ifr_ifru.copy_from_slice(sin_bytes);
    let ret = unsafe { libc::ioctl(fd, request, &mut ifr as *mut IfReq) };
    if ret < 0 {
        return Err(GuestInitError::Network(format!(
            "set_addr({}) failed: {}",
            name,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn add_default_route(fd: i32, gateway: [u8; 4], dev: &str) -> Result<(), GuestInitError> {
    let c_dev = CString::new(dev).map_err(|e| GuestInitError::Network(e.to_string()))?;
    let mut rt: RtEntry = unsafe { std::mem::zeroed() };
    let gw = sockaddr_in_from_ip(gateway);
    unsafe {
        std::ptr::copy_nonoverlapping(
            &gw as *const libc::sockaddr_in as *const u8,
            &mut rt.rt_gateway as *mut libc::sockaddr as *mut u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
    // rt_dst and rt_genmask remain 0.0.0.0 (default route).
    rt.rt_flags = (RTF_UP | RTF_GATEWAY) as libc::c_short;
    rt.rt_dev = c_dev.as_ptr() as *mut libc::c_char;
    let ret = unsafe { libc::ioctl(fd, SIOCADDRT, &mut rt as *mut RtEntry) };
    if ret < 0 {
        return Err(GuestInitError::Network(format!(
            "SIOCADDRT failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn sockaddr_in_from_ip(ip: [u8; 4]) -> libc::sockaddr_in {
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as u16;
    // `ip` is already in network byte order; from_ne_bytes copies the octets
    // verbatim into s_addr's memory representation.
    sin.sin_addr.s_addr = u32::from_ne_bytes(ip);
    sin
}
