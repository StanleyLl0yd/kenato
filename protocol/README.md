# Kenato Protocol

The Kenato wire protocol is platform-independent and versioned independently of Android and server releases.

## Current state

M0 defines only the outer server-routable envelope. It does **not** define the cryptographic session protocol yet.

The current schema lives under:

`protocol/kenato/v1/`

## Rules

- Unknown protocol versions must fail safely.
- Old wire data must never be silently reinterpreted with new semantics.
- Protocol changes must consider compatibility, malformed input, replay, duplication, and reordering.
- Deterministic test vectors are required when cryptographic protocol state is introduced.
- Private identity keys and plaintext user content never belong in this protocol's server-visible envelope.

Numeric resource limits are enforced by implementations/configuration and documented alongside the relevant protocol behavior.
