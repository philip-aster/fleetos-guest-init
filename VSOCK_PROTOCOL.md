# fleetos-guest-init ⇄ fleetos-agent VSOCK protocol (v1)

This is the byte-level contract the Core Lead implements the `vsock-attest`
verifier (CR-CORE-6) against. Any change requires a version bump and MUST be
mirrored on both sides.

## Transport
- AF_VSOCK, SOCK_STREAM, blocking.
- Guest context ID connects to HOST_CID = 2, port = 0x4649 (VSOCK_PORT).
- The agent listens on that port (one listener per hosting agent).

## Framing
Every message is `[u32 little-endian length][postcard payload]`.
Max message size: 16 MiB (guest aborts on anything larger).

## Message sequence
1. Agent -> Guest: `VsockAttestationChallenge`
2. Guest -> Agent: `VsockAttestationProof`
3. Agent -> Guest: `AgentAttestResult`          (MUST be sent; do not just close)
4. If accepted, Agent -> Guest: `WorkloadConfig`

## quote_type values
| value | meaning |
|-------|---------|
| 0     | TPM2 (vTPM) |
| 1     | SEV-SNP |
| 2     | TDX |
| 0xFF  | Dev software quote — MUST be rejected in production (fail-closed) |

## Security invariants
- The guest MUST bind its quote to the challenge nonce. The verifier MUST
  reject a quote whose embedded nonce does not match.
- `guest_x25519_pubkey` is the sealing target for workload secrets
  (corresponds to `AttestationQuote.agent_x25519_pubkey` in identity.proto).
- Unknown/unsupported `quote_type` MUST be rejected fail-closed.
- Protocol-version mismatch MUST be rejected.

## Structs
See `src/protocol.rs` (authoritative). The round-trip tests there pin the
postcard layout.

## Recommendation
Promote these structs into `fleetos-core` under the `vsock-attest` feature so
guest-init and the agent verifier share one definition and cannot drift.
