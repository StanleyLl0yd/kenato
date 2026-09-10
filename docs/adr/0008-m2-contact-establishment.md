# ADR 0008 — M2 invite and contact establishment

Status: Accepted  
Date: 2026-09-10

## Context

M2 is the first milestone in which Kenato publishes public identity material and allows two devices to establish a durable local contact binding. It must preserve invite-only discovery, avoid public enumeration, keep private identity/prekey material on-device, and stop before M3 session-ratchet state.

The accepted discovery baseline requires cryptographically random single-use invites with a 24-hour expiry and hash-at-rest storage where practical. The M1 identity model provides an ECDSA P-256 identity key, a signed P-256 prekey, and bounded one-time prekeys.

## Decision

M2 uses a narrow HTTPS API and an explicitly versioned `kenato.v1` Protocol Buffers contract with these boundaries:

- a client may publish only its identity id, identity public key, current signed prekey, signed-prekey signature, publication revision, and a bounded set of one-time public prekeys;
- publication is authenticated by a SHA-256/ECDSA P-256 signature from the long-lived identity key over the domain-separated canonical publication payload defined in `protocol/README.md`;
- the server derives and verifies the 32-byte identity id as SHA-256 of the exact X.509 SubjectPublicKeyInfo identity key, verifies that the key is P-256, verifies the M1 signed-prekey signature, and verifies the M2 publication signature before accepting publication;
- publication revisions are positive and monotonic. An exact replay of an already accepted revision may be treated idempotently; a different payload at the same or an older revision is rejected;
- invite tokens are generated on the client as 32 cryptographically random bytes, encoded as unpadded Base64url in links, single-use, and expire 24 hours after server acceptance;
- invite creation is authenticated by the creator identity key over the exact creator identity id and token, making token-to-creator binding verifiable by the eventual redeemer rather than trusted only to the server;
- the server stores only SHA-256 hashes of invite tokens, plus the minimum creator identity id, creation/expiry timestamps, and temporary redemption state. The raw invite token exists only transiently while a bounded request is processed;
- invitation links use the fixed form `kenato://invite/v1/<creator-identity-id>/<invite-token>/<invite-signature>`; QR codes contain that exact URI;
- redemption atomically changes an unexpired invite from unused to redeemed and returns the creator's authenticated current public identity bundle;
- the redeemer signs the creator identity id, its own identity id, and the invite token. The server retains that bounded redemption proof only until the creator claims the completed invite or the invite record expires;
- the creator claims a completed invite only by presenting the token and a valid creator identity signature over the canonical claim payload; the response contains the redeemer's authenticated public bundle and redemption proof;
- the redeemer verifies creator identity id derivation, creator bundle signatures, and the invite signature from the URI before pinning; the creator performs the analogous checks on the redeemer bundle and redemption proof before pinning;
- server-visible M2 state contains public key material and invite lifecycle metadata only; no private keys, message plaintext, contact display names, address-book data, or M3 session keys are stored;
- there is no public identity lookup or search endpoint. Creator public material is disclosed only to a requester holding an unexpired invite token; redeemer public material is disclosed only to the authenticated creator holding the same token;
- both clients pin the peer identity id and exact identity public key locally on first accepted contact establishment;
- a later observation of the same identity id with different identity-public-key bytes, or an attempt to replace an existing local contact binding with a different identity id, fails closed and is never auto-accepted;
- M2 publishes public prekeys but intentionally does not define one-time-prekey claim/consumption, Diffie-Hellman session-key derivation, Double Ratchet state, encrypted messages, or mailbox behavior. Those belong to M3/M4.

All fields, request bodies, retained prekey counts, invite attempts, and expensive signature verifications are explicitly bounded. Pre-authentication rate limits apply before expensive cryptographic verification where practical, followed by authenticated per-identity quotas. Server persistence uses SQLite in WAL mode as already established by the architecture baseline.

## Compatibility

M2 extends the existing `kenato.v1` package in a new `contact.proto` file without changing the meaning or field numbers of `Envelope`. Unknown protobuf fields remain forward-compatible. Unsupported `protocol_version` values fail explicitly rather than being reinterpreted.

Canonical signature payloads are defined independently of protobuf serialization so signature verification is stable across implementations and unknown-field handling. Deterministic framing vectors live in `docs/security/M2_TEST_VECTORS.md`.

## Consequences

Benefits:

- invite-only discovery remains non-enumerable;
- token-to-creator and redemption-to-redeemer bindings are end-to-end verifiable rather than relying solely on an honest server;
- server compromise exposes public keys and temporary invite/social metadata but not private identity keys or user-content plaintext;
- replay/downgrade of identity publications is bounded by monotonic revisions;
- M2 creates a durable contact-identity trust anchor without prematurely implementing M3 cryptographic session state.

Trade-offs:

- the server observes that two identity ids are temporarily related while an invite is redeemed and waiting to be claimed;
- devices must retain an invite token until the creator has claimed the result or it expires;
- M2 introduces server persistence and signature-verification work that requires explicit abuse limits;
- availability still depends on the server and TLS transport; a malicious server can deny service even though it cannot silently substitute another identity without signature/hash checks failing.

## Security review

This ADR changes invite-handshake, authentication, public identity publication, server persistence, and local contact-pinning boundaries. `docs/security/THREAT_MODEL.md` is updated as M2 implementation lands, and the milestone is not complete until malformed/oversized/replay/duplicate/substitution cases and exact-head repository security gates pass.
