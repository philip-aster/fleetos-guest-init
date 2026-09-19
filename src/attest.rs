// SPDX-License-Identifier: Apache-2.0
//! Attestation quote generation seam.
//!
//! Production MUST use a hardware-backed generator (vTPM / SEV-SNP / TDX).
//! The choice of mechanism is a Lead Architect decision; until it lands this
//! crate only provides the trait and a feature-gated dev placeholder.

use crate::error::GuestInitError;
#[cfg(feature = "dev-attest")]
use crate::protocol::QUOTE_TYPE_DEV_SOFTWARE;

/// Generates a hardware attestation quote bound to a fresh nonce.
pub trait QuoteGenerator {
    fn quote_type(&self) -> u8;
    fn generate_quote(&self, nonce: &[u8; 32]) -> Result<Vec<u8>, GuestInitError>;
}

/// Development/testing software quote generator. NOT a real attestation.
/// The agent-side `vsock-attest` verifier MUST reject `QUOTE_TYPE_DEV_SOFTWARE`
/// in production builds (fail-closed).
#[cfg(feature = "dev-attest")]
pub struct DevSoftwareQuoteGenerator;

#[cfg(feature = "dev-attest")]
impl QuoteGenerator for DevSoftwareQuoteGenerator {
    fn quote_type(&self) -> u8 {
        QUOTE_TYPE_DEV_SOFTWARE
    }
    fn generate_quote(&self, nonce: &[u8; 32]) -> Result<Vec<u8>, GuestInitError> {
        let mut quote = Vec::with_capacity(64);
        quote.extend_from_slice(b"FLEETOS-DEV-QUOTE-V1\0");
        quote.extend_from_slice(nonce);
        Ok(quote)
    }
}

/// Select the quote generator for this environment. Fail-closed: without a
/// hardware-backed generator (or the `dev-attest` feature) this errors and
/// the handshake aborts.
pub fn select_quote_generator() -> Result<Box<dyn QuoteGenerator>, GuestInitError> {
    // Production: prefer a hardware-backed generator when available.
    if let Some(generation) = hardware_generator() {
        return Ok(generation);
    }
    dev_generator().ok_or_else(|| {
        GuestInitError::Attest(
            "no attestation quote generator available (hardware backend not present, \
             dev-attest not enabled)"
                .into(),
        )
    })
}

fn hardware_generator() -> Option<Box<dyn QuoteGenerator>> {
    // TODO(Lead Architect decision): vTPM / SEV-SNP / TDX detection + impl.
    None
}

#[cfg(feature = "dev-attest")]
fn dev_generator() -> Option<Box<dyn QuoteGenerator>> {
    eprintln!("[fleetos-guest-init] WARNING: using DEV software quote generator (INSECURE)");
    Some(Box::new(DevSoftwareQuoteGenerator))
}

#[cfg(not(feature = "dev-attest"))]
fn dev_generator() -> Option<Box<dyn QuoteGenerator>> {
    None
}
