// SPDX-License-Identifier: Apache-2.0
//! fleetos-guest-init — PID 1 inside every Cloud Hypervisor MicroVM.

mod attest;
mod environment;
mod error;
mod exec;
mod network;
mod protocol;
mod vsock;

use error::GuestInitError;
use protocol::{
    AgentAttestResult, PROTOCOL_VERSION, VsockAttestationChallenge, VsockAttestationProof,
};

fn main() {
    if let Err(e) = run() {
        // As PID 1, exiting triggers a kernel panic — the correct fail-closed
        // behavior when the guest cannot be securely initialized.
        eprintln!("[fleetos-guest-init] FATAL: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), GuestInitError> {
    eprintln!("[fleetos-guest-init] starting");

    // 1. Connect to the host agent over AF_VSOCK.
    let fd = vsock::connect()?;
    eprintln!("[fleetos-guest-init] vsock connected");

    // 2. Receive the attestation challenge.
    let challenge: VsockAttestationChallenge = protocol::read_msg(fd)?;
    if challenge.protocol_version != PROTOCOL_VERSION {
        return Err(GuestInitError::Protocol(format!(
            "protocol version mismatch: agent={}, guest={}",
            challenge.protocol_version, PROTOCOL_VERSION
        )));
    }

    // 3. Generate the sealing keypair and the attestation quote.
    let (sealing_secret, sealing_pubkey) = fleetos_core::crypto::generate_sealing_keypair();
    let generator = attest::select_quote_generator()?;
    let raw_quote = generator.generate_quote(&challenge.nonce)?;
    let proof = VsockAttestationProof {
        quote_type: generator.quote_type(),
        raw_quote,
        guest_x25519_pubkey: sealing_pubkey.0,
    };

    // 4. Send the proof.
    protocol::write_msg(fd, &proof)?;
    eprintln!("[fleetos-guest-init] attestation proof sent");

    // 5. Receive the verification result.
    let result: AgentAttestResult = protocol::read_msg(fd)?;
    if !result.accepted {
        return Err(GuestInitError::Attest(format!(
            "agent rejected quote: {}",
            result.reason
        )));
    }

    // 6. Receive the workload configuration.
    let config: protocol::WorkloadConfig = protocol::read_msg(fd)?;
    eprintln!("[fleetos-guest-init] workload config received");

    // Attestation + config done; close the VSOCK channel.
    vsock::close(fd);

    // 7. Set up the environment. Network is deliberately NOT up yet
    //    (boot-race invariant).
    environment::setup(&config, &*sealing_secret)?;
    eprintln!("[fleetos-guest-init] environment ready");

    // 8. Bring up networking AFTER attestation + config (boot-race invariant).
    network::bring_up(&config)?;
    eprintln!("[fleetos-guest-init] network up");

    // 9. Exec the workload. Replaces PID 1; does not return on success.
    exec::exec_workload(&config)?;
    Ok(())
}
