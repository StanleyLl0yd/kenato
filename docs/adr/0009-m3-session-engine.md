# ADR 0009 — M3 E2EE session engine

Status: Accepted  
Date: 2026-09-10

## Context

M3 must add asynchronous one-to-one session establishment and a Double Ratchet without replacing the M1/M2 Kenato identity trust anchor or inventing a new ratchet implementation.

The existing long-lived Kenato identity is an Android Keystore-backed ECDSA P-256 signing key. M2 pins that exact identity public key locally and authenticates invite/contact establishment with it. M3 therefore needs a reviewed ratchet engine whose protocol-specific keys can be bound to that already-pinned identity rather than silently becoming a second independent user identity.

Dependency choice is also a security and distribution decision. ADR 0006 intentionally keeps the pre-1.0 Kenato source tree source-visible but without a repository-wide open-source license. A crypto library that would force a copyleft licensing decision cannot be adopted implicitly.

## Decision

M3 uses **vodozemac 0.10.0**, specifically its one-to-one **Olm** implementation, as the cryptographic session engine.

The dependency is exact-pinned to `=0.10.0` when the native integration lands and its resolved Rust dependency graph is committed in `Cargo.lock`. M3 uses `olm::SessionConfig::version_1()` only. Experimental session configurations, Megolm/group ratchets, low-level/hazmat APIs, fallback keys, and custom modifications to vodozemac cryptography are out of scope.

The selected release:

- is a pure-Rust implementation of Olm/Double Ratchet;
- implements asynchronous 3DH session establishment with Curve25519 account and one-time keys;
- is Apache-2.0 licensed, which does not require changing ADR 0006 merely to consume the dependency;
- declares Rust 1.85 as its minimum supported Rust version;
- has a published independent Least Authority security audit with no significant findings according to the upstream release documentation;
- internally bounds out-of-order handling: vodozemac 0.10.0 retains at most 40 skipped message keys and rejects message gaps larger than 2000.

Kenato will integrate the Rust library behind a deliberately small Android JNI boundary. The bridge may marshal bounded inputs/outputs and serialize/restore opaque engine state, but it must not reimplement, fork, weaken, or expose low-level ratchet cryptography. Rust/NDK/cargo tooling and Android ABI support must be exact-versioned and verified in CI when the bridge is introduced.

## Kenato identity binding

The M1/M2 ECDSA P-256 identity remains the sole Kenato contact trust anchor.

Each installation creates one persistent vodozemac Olm `Account`, which contains its own Ed25519 fingerprint key and Curve25519 3DH identity key. These engine keys are **session identity material**, not a replacement Kenato identity.

Before another client may use them, the owner signs a Kenato-owned canonical M3 session-bootstrap payload with the existing P-256 identity key. The payload binds:

- M3 protocol version;
- exact 32-byte Kenato identity id;
- positive session-account generation;
- positive session-publication revision;
- exact 32-byte Olm Ed25519 public key;
- exact 32-byte Olm Curve25519 public key;
- a bounded, unique, canonically ordered set of Curve25519 one-time public keys.

The peer first verifies the existing M2 identity id/public key pin, then verifies this P-256 signature, then pins the exact M3 account generation and engine identity-key bytes. A server cannot substitute a different Olm account without causing the P-256 binding or the local session-identity pin to fail.

A session account is not silently regenerated after corruption, missing key material, or an unexpected key change. Session-account recovery is explicit and invalidates affected M3 sessions; already-pinned peers must not silently accept the replacement account generation.

## One-time keys and initiator rule

Kenato uses vodozemac Curve25519 one-time keys for the Olm 3DH bootstrap. It does **not** use Olm fallback keys in M3. If an authenticated one-time key is unavailable, new session establishment fails/retries rather than weakening the initial bootstrap by silently reusing a fallback key.

The local target pool is 32 one-time keys and the protocol hard maximum is 50, matching the selected engine's published server-facing maximum while staying below M2's active-invite quota relationship and wire-size limits. The server only stores public one-time keys and allocation state.

For a contact created through an invite, the **invite redeemer is the M3 session initiator** and the invite creator is the responder. This removes simultaneous first-session races and gives one deterministic session per new contact.

During M3 contact completion the server atomically allocates one creator one-time session key to that redeemed invite. The redeemer verifies the creator's signed M3 bootstrap before using the allocated key, creates the outbound Olm session, and produces an Olm pre-key initialization frame. The frame is an opaque bounded ciphertext to the server. The creator accepts it only after claiming the same invite, verifying the redeemer's pinned Kenato identity and signed M3 account binding, and requiring the inbound pre-key message to contain the exact expected redeemer Curve25519 identity key.

The initialization plaintext is protocol control data, not user content, and is canonically bound to both Kenato identity ids, both M3 account generations, and the invite token hash so an otherwise valid pre-key frame cannot be transplanted to another contact/invite context.

The exact server/API transaction split is specified by the M3 protocol/server slice; the invariant is that a creator claim must not silently complete an M3 contact without the authenticated session-init material needed to create the matching inbound session.

## Session-message boundary

M3 exposes only a crypto/session primitive to the application layer:

- create/accept the initial session;
- encrypt a bounded byte payload into an opaque Olm pre-key/normal message;
- decrypt a bounded Olm message;
- serialize and restore session state.

M3 does not add conversation UI, WebSocket routing, an offline mailbox, delivery acknowledgements, message history, or other M4 product behavior.

Kenato-owned envelopes explicitly carry the engine message type (`pre-key` or `normal`) and opaque ciphertext bytes. The server does not parse or decrypt Olm ciphertext.

Application plaintext accepted by the M3 primitive is capped at 64 KiB and serialized M3 ciphertext/envelopes are capped at 96 KiB so M3 cannot later bypass the planned M4 envelope bound.

## Replay, reordering, and skipped keys

Kenato relies on the selected Olm implementation for Double Ratchet message-key evolution and authenticated ciphertext processing; it does not reproduce those mechanisms in Kotlin or Go.

M3 additionally applies bounded Kenato session-state rules:

- at most one active M3 session per pinned contact in the initial implementation;
- at most 256 persisted contact sessions, matching the bounded M2 contact-pin scale;
- duplicate/replayed messages that the engine can no longer authenticate/decrypt are rejected and never treated as fresh plaintext;
- vodozemac's fixed skipped-message-key store and maximum message-gap checks remain enabled and are covered by integration tests;
- no caller-controlled override may raise the engine's skipped-key/message-gap bounds;
- malformed or oversized engine messages are rejected before or around native parsing with fixed Kenato limits.

## Persistence and crash safety

Ratchet rollback can cause key reuse or replay acceptance, so persistence ordering is part of the cryptographic boundary.

For every outbound encryption, the advanced session snapshot must be durably committed **before** ciphertext is returned to a caller that can transmit it. If the commit fails, the produced ciphertext is discarded and the operation fails closed.

For inbound decryption or inbound session creation, the advanced session state and any consumed account one-time key must be durably committed **before** plaintext is returned to application code. If the commit fails, plaintext is discarded and the operation fails closed.

Account/session snapshots are app-private and backup/device-transfer excluded. A fresh cryptographically random 32-byte pickle key is used for every vodozemac encrypted snapshot; pickle keys are themselves protected with a non-exportable Android Keystore AES-GCM wrapping key and are zeroed from ordinary process buffers when practical. Reusing a pickle key across changing snapshots is forbidden because the upstream pickle format deterministically derives its IV from that key.

Multi-record updates that must move together, such as consuming an account one-time key while creating an inbound session, require one local transaction/atomic commit. Corrupt, missing, mismatched, downgraded, or partially committed state fails closed rather than silently creating a new session/account.

## Alternatives considered

### Signal `libsignal`

Not selected for M3. It is a mature implementation of the Signal Protocol and Double Ratchet, but current upstream explicitly states that use outside Signal is unsupported and licenses the library under GNU AGPLv3. Adopting it now would couple Kenato's crypto dependency to an unsupported external API and could force a project/distribution licensing decision that ADR 0006 reserves to the owner.

This is a licensing/maintenance decision, not a criticism of Signal Protocol security.

### Legacy `libolm`

Not selected. Although its Olm protocol is compatible in concept and its license is permissive, upstream has deprecated the C/C++ implementation in favor of vodozemac because of memory-safety and historical security concerns. Starting a new Android integration on the deprecated implementation would add avoidable native risk.

### New Kenato Double Ratchet implementation

Rejected. Implementing the ratchet directly from a specification would violate the repository rule to prefer a mature reviewed implementation and would create unnecessary cryptographic review burden.

## Compatibility

M3 adds new versioned session-bootstrap/session-envelope protocol messages without changing the meaning of existing M1/M2 identity and invite signatures. The P-256 Kenato identity id remains stable.

M3-specific canonical signature/control payloads are independent of protobuf serialization. Unsupported protocol/engine versions fail explicitly; there is no automatic downgrade to an unauthenticated or non-ratcheted mode.

Because Kenato is pre-1.0 and M3 has not shipped, no production migration from an earlier session format is required. Nevertheless persisted M3 state and wire messages are versioned from their first implementation so future changes cannot silently reinterpret them.

## Consequences

Benefits:

- Kenato reuses a reviewed memory-safe Double Ratchet engine instead of implementing cryptography itself;
- Apache-2.0 dependency licensing preserves the current pre-1.0 licensing decision space;
- the existing P-256 contact identity remains the user-visible trust anchor;
- deterministic invite roles avoid simultaneous initial-session races;
- one-time-key exhaustion fails closed instead of silently weakening bootstrap semantics;
- persistence ordering explicitly protects against ratchet rollback/key reuse after crashes.

Trade-offs:

- Android gains a Rust/JNI/NDK build boundary that must be supply-chain pinned and tested across supported ABIs;
- vodozemac implements Olm rather than Signal's X3DH/Signal session format, so Kenato is protocol-compatible only with Kenato clients, not Signal or Matrix clients;
- the engine's public API and upstream format still require version pinning and migration review before upgrades;
- session account recovery cannot be invisible because replacing engine identity material would invalidate existing M3 pins/sessions;
- deterministic redeemer initiation couples first-session establishment to the invite completion lifecycle.

## References

- vodozemac 0.10.0 release and source: <https://github.com/matrix-org/vodozemac/releases/tag/0.10.0>
- vodozemac audit link published by upstream: <https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf>
- Signal libsignal repository/license statement: <https://github.com/signalapp/libsignal>
- Olm protocol background: <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md>

## Security review

This decision introduces a new cryptographic engine, native/JNI boundary, additional long-lived secret state, one-time-key allocation, and crash-sensitive ratchet persistence. `docs/security/THREAT_MODEL.md` must be updated as implementation lands. M3 exit requires native integration tests, malformed/oversized/replay/reordering/skipped-key tests, persistence/restart/corruption tests, dependency/supply-chain review, exact-head security gates, squash merge, and exact-main verification before M4 begins.
