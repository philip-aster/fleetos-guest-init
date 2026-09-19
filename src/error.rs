// SPDX-License-Identifier: Apache-2.0
use std::fmt;

#[derive(Debug)]
pub enum GuestInitError {
    Vsock(String),
    Io(std::io::Error),
    Protocol(String),
    Attest(String),
    Environment(String),
    Network(String),
    Exec(String),
}

impl fmt::Display for GuestInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuestInitError::Vsock(s) => write!(f, "vsock: {}", s),
            GuestInitError::Io(e) => write!(f, "io: {}", e),
            GuestInitError::Protocol(s) => write!(f, "protocol: {}", s),
            GuestInitError::Attest(s) => write!(f, "attestation: {}", s),
            GuestInitError::Environment(s) => write!(f, "environment: {}", s),
            GuestInitError::Network(s) => write!(f, "network: {}", s),
            GuestInitError::Exec(s) => write!(f, "exec: {}", s),
        }
    }
}

impl std::error::Error for GuestInitError {}

impl From<std::io::Error> for GuestInitError {
    fn from(e: std::io::Error) -> Self {
        GuestInitError::Io(e)
    }
}
