// SPDX-License-Identifier: Apache-2.0
//! Environment setup: pseudo-filesystems, writable /etc, sealing key install,
//! /etc/hosts, and EmptyDir volume mounts.

use std::ffi::CString;
use std::fs;

use fleetos_core::naming::dummy_ip_hostname;

use crate::error::GuestInitError;
use crate::protocol::WorkloadConfig;

/// Well-known location where the workload's X25519 sealing private key is
/// installed for pickup. OPEN QUESTION: see README (secret-delivery design).
const SEALING_KEY_PATH: &str = "/run/fleetos/sealing_key";
const SVID_CERT_PATH: &str = "/run/fleetos/svid.crt";
const SVID_KEY_PATH: &str = "/run/fleetos/svid.key";

pub fn setup(config: &WorkloadConfig, sealing_key: &[u8]) -> Result<(), GuestInitError> {
    mount_pseudo_filesystems()?;
    write_minimal_etc_files()?;
    install_sealing_key(sealing_key)?;
    install_svid(config)?;
    install_secrets(config)?;
    write_hosts(config)?;
    mount_volumes(config)?;
    Ok(())
}

fn mount_pseudo_filesystems() -> Result<(), GuestInitError> {
    mount("proc", "/proc", "proc", 0)?;
    mount("sysfs", "/sys", "sysfs", 0)?;
    mount("tmpfs", "/run", "tmpfs", 0)?;
    mount("tmpfs", "/tmp", "tmpfs", 0)?;
    // The erofs rootfs is read-only, so /etc must be overlaid with a writable
    // tmpfs. Trade-off: image /etc content is shadowed; we provide the minimal
    // set below. Flagged for confirmation.
    mount("tmpfs", "/etc", "tmpfs", 0)?;
    // /dev: best-effort devtmpfs; fall back to tmpfs if unavailable.
    if mount("devtmpfs", "/dev", "devtmpfs", 0).is_err() {
        mount("tmpfs", "/dev", "tmpfs", 0)?;
    }
    Ok(())
}

fn mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
) -> Result<(), GuestInitError> {
    fs::create_dir_all(target).map_err(GuestInitError::Io)?;
    let c_source = CString::new(source).map_err(|e| GuestInitError::Environment(e.to_string()))?;
    let c_target = CString::new(target).map_err(|e| GuestInitError::Environment(e.to_string()))?;
    let c_fstype = CString::new(fstype).map_err(|e| GuestInitError::Environment(e.to_string()))?;
    let ret = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(GuestInitError::Environment(format!(
            "mount({}, {}) failed: {}",
            fstype,
            target,
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn write_minimal_etc_files() -> Result<(), GuestInitError> {
    fs::write(
        "/etc/passwd",
        "root:x:0:0:root:/:/bin/sh\nnobody:x:65534:65534:nobody:/:/nonexistent:/usr/sbin/nologin\n",
    )
    .map_err(GuestInitError::Io)?;
    fs::write("/etc/group", "root:x:0:\nnogroup:x:65534:\n").map_err(GuestInitError::Io)?;
    fs::write(
        "/etc/resolv.conf",
        "# FleetOS uses /etc/hosts for service resolution\nnameserver 127.0.0.1\n",
    )
    .map_err(GuestInitError::Io)?;
    Ok(())
}

fn install_sealing_key(sealing_key: &[u8]) -> Result<(), GuestInitError> {
    fs::create_dir_all("/run/fleetos").map_err(GuestInitError::Io)?;
    fs::write(SEALING_KEY_PATH, sealing_key).map_err(GuestInitError::Io)?;
    chmod(SEALING_KEY_PATH, 0o600)?;
    Ok(())
}

fn install_svid(config: &WorkloadConfig) -> Result<(), GuestInitError> {
    if !config.svid_cert_chain_der.is_empty() {
        fs::write(SVID_CERT_PATH, &config.svid_cert_chain_der[0]).map_err(GuestInitError::Io)?;
        chmod(SVID_CERT_PATH, 0o644)?;
    }
    if !config.svid_private_key_der.is_empty() {
        fs::write(SVID_KEY_PATH, &config.svid_private_key_der).map_err(GuestInitError::Io)?;
        chmod(SVID_KEY_PATH, 0o600)?;
    }
    Ok(())
}

/// CORE-WI-7: Write delivered secrets to `/run/fleetos/secrets/{name}`.
///
/// Fail-closed: any validation or write error aborts setup, so the workload
/// never starts missing an authorized secret.
///
/// Path traversal defense: guest-init is PID 1 running as root inside the
/// VM. Names originate upstream (agent → WorkloadConfig), but we validate
/// here regardless — reject `/`, `..` components, and empty names.
///
/// Never log secret bytes. Names and sizes are loggable; content is not.
fn install_secrets(config: &WorkloadConfig) -> Result<(), GuestInitError> {
    if config.secrets.is_empty() {
        return Ok(());
    }

    const SECRETS_DIR: &str = "/run/fleetos/secrets";

    fs::create_dir_all(SECRETS_DIR).map_err(GuestInitError::Io)?;

    for (name, bytes) in &config.secrets {
        // Validate the name before touching the filesystem.
        if name.is_empty() {
            return Err(GuestInitError::Environment(
                "secret name is empty".to_string(),
            ));
        }
        if name.contains('/') || name.contains('\\') {
            return Err(GuestInitError::Environment(format!(
                "secret name contains path separator: {:?}",
                name
            )));
        }
        if name == "." || name == ".." || name.split('.').any(|c| c == "..") {
            return Err(GuestInitError::Environment(format!(
                "secret name contains traversal component: {:?}",
                name
            )));
        }
        // Reject names that would resolve outside SECRETS_DIR (belt-and-suspenders).
        let target = format!("{}/{}", SECRETS_DIR, name);
        if target.contains("..") {
            return Err(GuestInitError::Environment(format!(
                "secret name resolves outside secrets directory: {:?}",
                name
            )));
        }

        // Write the secret file with mode 0600 (owner read/write only).
        fs::write(&target, bytes).map_err(GuestInitError::Io)?;
        chmod(&target, 0o600)?;

        // Log name + size only. NEVER log secret bytes.
        eprintln!(
            "[fleetos-guest-init] secret installed: {} ({} bytes)",
            name,
            bytes.len()
        );
    }

    Ok(())
}

fn write_hosts(config: &WorkloadConfig) -> Result<(), GuestInitError> {
    let mut hosts = String::new();
    hosts.push_str("# Generated by fleetos-guest-init\n");
    hosts.push_str("127.0.0.1 localhost\n");
    hosts.push_str("::1 localhost\n");
    for route in &config.dummy_ip_routes {
        // CR-CORE-7 invariant: MUST use the core canonical hostname convention.
        let hostname = dummy_ip_hostname(
            &route.service,
            &route.role,
            &route.tenant,
            &config.trust_domain,
        )
        .map_err(|e| GuestInitError::Environment(format!("hostname build failed: {}", e)))?;
        let ip = std::net::Ipv4Addr::from(route.dummy_ip);
        hosts.push_str(&format!("{} {}\n", ip, hostname));
    }
    fs::write("/etc/hosts", hosts).map_err(GuestInitError::Io)?;
    Ok(())
}

fn mount_volumes(config: &WorkloadConfig) -> Result<(), GuestInitError> {
    for vol in &config.volume_mounts {
        let flags = if vol.read_only { libc::MS_RDONLY } else { 0 };
        mount("tmpfs", &vol.mount_path, "tmpfs", flags as libc::c_ulong)?;
    }
    Ok(())
}

fn chmod(path: &str, mode: u32) -> Result<(), GuestInitError> {
    let c = CString::new(path).map_err(|e| GuestInitError::Environment(e.to_string()))?;
    let ret = unsafe { libc::chmod(c.as_ptr(), mode) };
    if ret < 0 {
        return Err(GuestInitError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}
