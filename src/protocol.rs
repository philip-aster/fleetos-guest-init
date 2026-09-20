// SPDX-License-Identifier: Apache-2.0
//! VSOCK attestation + configuration wire protocol — re-exported from core.
//!
//! All wire types, quote-type constants, and pure framing helpers live in
//! `fleetos_core::vsock_proto` (feature `vsock-attest`), the single source of
//! truth shared with `fleetos-agent`. This module re-exports them and adds the
//! libc-backed socket I/O wrappers (`read_msg`/`write_msg`), which are
//! guest-init's responsibility per the "core owns the convention, consumers
//! own the I/O" rule.

use serde::{Serialize, de::DeserializeOwned};

// Single source of truth: types, constants, and pure framing from core.
pub use fleetos_core::vsock_proto::*;

use crate::error::GuestInitError;
use crate::vsock;

/// Serialize `msg` with the core framing helper and write
/// `[u32 LE length][postcard payload]` to `fd`.
pub fn write_msg<T: Serialize>(fd: i32, msg: &T) -> Result<(), GuestInitError> {
    let framed = frame_msg(msg).map_err(|e| GuestInitError::Protocol(e.to_string()))?;
    vsock::write_all(fd, &framed)?;
    Ok(())
}

/// Read `[u32 LE length][postcard payload]` from `fd`, enforce the
/// `MAX_MESSAGE_BYTES` cap, and decode with the core framing helper.
pub fn read_msg<T: DeserializeOwned>(fd: i32) -> Result<T, GuestInitError> {
    let mut len_buf = [0u8; 4];
    vsock::read_exact(fd, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(GuestInitError::Protocol(format!(
            "message too large: {} bytes (max {})",
            len, MAX_MESSAGE_BYTES
        )));
    }
    let mut buf = vec![0u8; len];
    vsock::read_exact(fd, &mut buf)?;
    decode_msg(&buf).map_err(|e| GuestInitError::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a message through the exact framing `write_msg`/`read_msg`
    /// use, locking the wire contract from the guest-init side.
    fn round_trip<T>(msg: &T) -> T
    where
        T: Serialize + DeserializeOwned,
    {
        let framed = frame_msg(msg).unwrap();
        // frame_msg emits [u32 LE length][payload]; decode_msg consumes the payload.
        let len = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        assert_eq!(framed.len(), 4 + len);
        decode_msg(&framed[4..]).unwrap()
    }

    #[test]
    fn challenge_round_trip() {
        let c = VsockAttestationChallenge {
            protocol_version: PROTOCOL_VERSION,
            nonce: [0xAB; 32],
        };
        let back: VsockAttestationChallenge = round_trip(&c);
        assert_eq!(back.nonce, c.nonce);
        assert_eq!(back.protocol_version, c.protocol_version);
    }

    #[test]
    fn proof_round_trip() {
        let p = VsockAttestationProof {
            quote_type: QUOTE_TYPE_TPM2,
            raw_quote: vec![1, 2, 3, 4],
            guest_x25519_pubkey: [0x11; 32],
        };
        let back: VsockAttestationProof = round_trip(&p);
        assert_eq!(back.quote_type, p.quote_type);
        assert_eq!(back.raw_quote, p.raw_quote);
        assert_eq!(back.guest_x25519_pubkey, p.guest_x25519_pubkey);
    }

    #[test]
    fn config_round_trip() {
        let c = WorkloadConfig {
            svid_cert_chain_der: vec![vec![0x30, 0x82]],
            svid_private_key_der: vec![0x04, 0x20],
            env_vars: vec![("FOO".to_string(), "bar".to_string())],
            volume_mounts: vec![VolumeMountConfig {
                name: "scratch".to_string(),
                mount_path: "/scratch".to_string(),
                read_only: false,
            }],
            dummy_ip_routes: vec![DummyIpRouteConfig {
                dummy_ip: [240, 0, 0, 45],
                service: "db".to_string(),
                role: "replica".to_string(),
                tenant: "acme".to_string(),
            }],
            workload_binary_path: "/usr/bin/app".to_string(),
            workload_args: vec!["--serve".to_string()],
            trust_domain: "fleet.example.internal".to_string(),
            tenant_id: "acme".to_string(),
            service_name: "db".to_string(),
            role: "replica".to_string(),
            guest_ip: [10, 0, 0, 2],
            netmask: [255, 255, 255, 0],
            gateway: [10, 0, 0, 1],
        };
        let back: WorkloadConfig = round_trip(&c);
        assert_eq!(back.workload_binary_path, c.workload_binary_path);
        assert_eq!(back.dummy_ip_routes[0].dummy_ip, [240, 0, 0, 45]);
        assert_eq!(back.guest_ip, [10, 0, 0, 2]);
    }
}
