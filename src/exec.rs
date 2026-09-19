// SPDX-License-Identifier: Apache-2.0
//! Exec hand-off: replace PID 1 with the workload via execve().

use std::ffi::CString;

use crate::error::GuestInitError;
use crate::protocol::WorkloadConfig;

/// Replace PID 1 with the workload. Only returns on error.
pub fn exec_workload(config: &WorkloadConfig) -> Result<(), GuestInitError> {
    let path = CString::new(config.workload_binary_path.as_str())
        .map_err(|e| GuestInitError::Exec(format!("bad path: {}", e)))?;
    let mut args: Vec<CString> = Vec::with_capacity(config.workload_args.len() + 1);
    args.push(path.clone());
    for a in &config.workload_args {
        args.push(
            CString::new(a.as_str())
                .map_err(|e| GuestInitError::Exec(format!("bad arg: {}", e)))?,
        );
    }
    let mut envs: Vec<CString> = Vec::with_capacity(config.env_vars.len() + 1);
    for (k, v) in &config.env_vars {
        envs.push(
            CString::new(format!("{}={}", k, v))
                .map_err(|e| GuestInitError::Exec(format!("bad env: {}", e)))?,
        );
    }
    if !config.env_vars.iter().any(|(k, _)| k == "PATH") {
        envs.push(CString::new("PATH=/usr/local/bin:/usr/bin:/bin").unwrap());
    }
    let arg_ptrs: Vec<*const libc::c_char> = args
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env_ptrs: Vec<*const libc::c_char> = envs
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    unsafe {
        libc::execve(path.as_ptr(), arg_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    // execve only returns on failure.
    Err(GuestInitError::Exec(format!(
        "execve({}) failed: {}",
        config.workload_binary_path,
        std::io::Error::last_os_error()
    )))
}
