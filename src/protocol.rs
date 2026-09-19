// SPDX-License-Identifier: Apache-2.0
//! VSOCK attestation + configuration wire protocol.
//!
//! This module is the byte-level contract between `fleetos-guest-init` (guest)
//! and `fleetos-agent` (host). The Core Lead implements the agent side
//! (`vsock-attest`, CR-CORE-6) against THIS contract. Any change here MUST be
//! mirrored on the agent side and in VSOCK_PROTOCOL.md.
//!
//! RECOMMENDATION: these structs should be promoted into `fleetos-core` under
//! the `vsock-attest` feature so guest-init and the agent verifier share one
//! definition and cannot drift.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::error::GuestInitError;
use crate::vsock;

/// Protocol version. Bumped on any breaking change to this contract.
pub const PROTOCOL_VERSION: u32 = 1;

/// Max accepted message size (guards against a malformed/huge length prefix).
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// AF_VSOCK port the host agent listens on for guest-init handshakes.
/// Must match the `fleetos-agent` listener.
pub const VSOCK_PORT: u32 = 0x4649;

/// AF_VSOCK context ID of the host.
pub const HOST_CID: u32 = 2; // VMADDR_CID_HOST

// --- Quote mechanism identifiers --------------------------------------------

// --- Quote mechanism identifiers --------------------------------------------
// Wire protocol constants (see VSOCK_PROTOCOL.md). Allowed dead_code because
// hardware backends (TPM2, SEV-SNP, TDX) are pending Lead Architect decision,
// and DEV_SOFTWARE is only used under the `dev-attest` feature gate.
#[allow(dead_code)]
pub const QUOTE_TYPE_TPM2: u8 = 0;
#[allow(dead_code)]
pub const QUOTE_TYPE_SEV_SNP: u8 = 1;
#[allow(dead_code)]
pub const QUOTE_TYPE_TDX: u8 = 2;
/// Development/testing software quote. The agent verifier MUST reject this in
/// production builds (fail-closed).
#[allow(dead_code)]
pub const QUOTE_TYPE_DEV_SOFTWARE: u8 = 0xFF;

// --- Messages ---------------------------------------------------------------

/// Agent -> Guest. Opens the handshake.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VsockAttestationChallenge {
    pub protocol_version: u32,
    /// Fresh random 32-byte nonce. The guest MUST bind its quote to this.
    pub nonce: [u8; 32],
}

/// Guest -> Agent. The attestation proof.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VsockAttestationProof {
    /// One of the `QUOTE_TYPE_*` constants.
    pub quote_type: u8,
    /// Mechanism-specific quote bytes, bound to the challenge nonce.
    pub raw_quote: Vec<u8>,
    /// The guest workload's X25519 sealing public key (32 bytes), generated
    /// fresh this boot. The agent seals workload secrets to this key.
    /// Semantically matches `AttestationQuote.agent_x25519_pubkey` in
    /// identity.proto.
    pub guest_x25519_pubkey: [u8; 32],
}

/// Agent -> Guest. Result of quote verification. Sent before `WorkloadConfig`
/// (on success) and instead of it (on failure).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentAttestResult {
    pub accepted: bool,
    /// Human-readable reason when `accepted == false`. Empty otherwise.
    pub reason: String,
}

/// Agent -> Guest. Pushed after successful attestation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WorkloadConfig {
    /// Workload SVID certificate chain (DER), SPIFFE ID for mTLS.
    pub svid_cert_chain_der: Vec<Vec<u8>>,
    /// Workload SVID private key (DER).
    /// OPEN QUESTION: private-key delivery mechanism needs a decision (README).
    pub svid_private_key_der: Vec<u8>,
    /// Environment variables for the workload.
    pub env_vars: Vec<(String, String)>,
    /// EmptyDir scratch volumes to mount.
    pub volume_mounts: Vec<VolumeMountConfig>,
    /// Dummy-IP -> service/role/tenant routes used to build /etc/hosts.
    pub dummy_ip_routes: Vec<DummyIpRouteConfig>,
    /// Absolute path to the workload binary inside the rootfs.
    pub workload_binary_path: String,
    /// argv[1..] for the workload.
    pub workload_args: Vec<String>,
    /// Trust domain, used for canonical hostname construction.
    pub trust_domain: String,
    pub tenant_id: String,
    pub service_name: String,
    pub role: String,
    /// eth0 IPv4 address (network byte order). Zero = leave unconfigured.
    pub guest_ip: [u8; 4],
    /// eth0 netmask (network byte order).
    pub netmask: [u8; 4],
    /// Default gateway (network byte order). Zero = no default route.
    pub gateway: [u8; 4],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VolumeMountConfig {
    pub name: String,
    pub mount_path: String,
    pub read_only: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DummyIpRouteConfig {
    /// Dummy IPv4 in network byte order (matches RouteEntry.dummy_ip semantics).
    pub dummy_ip: [u8; 4],
    pub service: String,
    pub role: String,
    pub tenant: String,
}

// --- Framing ----------------------------------------------------------------

/// Serialize `msg` with postcard and write `[u32 LE length][payload]` to `fd`.
pub fn write_msg<T: Serialize>(fd: i32, msg: &T) -> Result<(), GuestInitError> {
    let payload =
        postcard::to_allocvec(msg).map_err(|e| GuestInitError::Protocol(e.to_string()))?;
    let len = (payload.len() as u32).to_le_bytes();
    vsock::write_all(fd, &len)?;
    vsock::write_all(fd, &payload)?;
    Ok(())
}

/// Read `[u32 LE length][payload]` from `fd` and deserialize with postcard.
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
    postcard::from_bytes(&buf).map_err(|e| GuestInitError::Protocol(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_round_trip() {
        let c = VsockAttestationChallenge {
            protocol_version: PROTOCOL_VERSION,
            nonce: [0xAB; 32],
        };
        let bytes = postcard::to_allocvec(&c).unwrap();
        let back: VsockAttestationChallenge = postcard::from_bytes(&bytes).unwrap();
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
        let bytes = postcard::to_allocvec(&p).unwrap();
        let back: VsockAttestationProof = postcard::from_bytes(&bytes).unwrap();
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
        let bytes = postcard::to_allocvec(&c).unwrap();
        let back: WorkloadConfig = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.workload_binary_path, c.workload_binary_path);
        assert_eq!(back.dummy_ip_routes[0].dummy_ip, [240, 0, 0, 45]);
        assert_eq!(back.guest_ip, [10, 0, 0, 2]);
    }
}
