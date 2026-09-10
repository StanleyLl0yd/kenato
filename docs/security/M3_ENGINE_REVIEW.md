# M3 Session Engine Review

Status: architecture selection for M3  
Date: 2026-09-10

This review records the dependency/security decision behind ADR 0009. It does not claim that the M3 native bridge or session persistence is implemented yet.

## Requirements

The M3 engine must provide a mature asynchronous one-to-one Double Ratchet implementation while preserving these Kenato constraints:

- the M1/M2 ECDSA P-256 identity remains the contact trust anchor;
- no private identity/session key is sent to the server;
- no home-grown ratchet or ad-hoc cryptographic construction;
- bounded out-of-order/skipped-key state;
- serializable state for crash-safe Android persistence;
- no silent downgrade or identity replacement;
- dependency licensing compatible with ADR 0006 without making an implicit repository-license decision;
- Android support can be built reproducibly and security-reviewed.

## Selected: vodozemac 0.10.0 / Olm

Upstream release: <https://github.com/matrix-org/vodozemac/releases/tag/0.10.0>

Selected properties verified against the tagged upstream source:

- package version: `0.10.0`;
- license: `Apache-2.0`;
- minimum Rust version: `1.85`;
- implementation language: Rust;
- M3 uses only the one-to-one `olm` account/session API and `SessionConfig::version_1()`;
- the account exposes persistent Ed25519 and Curve25519 public identity keys plus Curve25519 one-time keys;
- outbound session creation performs the engine's 3DH using the recipient Curve25519 identity key and one-time key;
- inbound session creation requires the caller-supplied expected sender Curve25519 identity key and rejects a mismatched pre-key message identity;
- the account removes the matching private one-time key as part of successful inbound-session creation;
- Olm ciphertext has an explicit pre-key/normal message type and bounded binary encoding suitable for wrapping in a Kenato-owned protobuf envelope;
- upstream documents an independent Least Authority audit with no significant findings.

The tagged implementation also has hard internal out-of-order bounds:

- `MAX_MESSAGE_KEYS = 40` retained skipped message keys;
- `MAX_MESSAGE_GAP = 2000`, after which decryption rejects the gap rather than deriving/storing an unbounded chain.

Kenato will not enable an API that changes those constants or exposes low-level message-key derivation.

## Persistence finding

Vodozemac's encrypted pickle helper derives its pickle cipher IV deterministically from the caller-provided pickle key. Reusing one pickle key across changing snapshots is therefore not acceptable for Kenato state persistence.

M3 persistence must use a **fresh cryptographically random 32-byte pickle key for every account/session snapshot**. Each ephemeral pickle key is wrapped with a non-exportable Android Keystore AES-GCM key and stored only alongside its corresponding encrypted pickle. The plaintext pickle key is zeroed from ordinary process buffers when practical.

This design keeps serialized engine secrets encrypted across the JNI boundary/storage path while avoiding pickle-key/IV reuse. Persistence code must include a regression test proving that a successful second snapshot uses a different pickle key/wrapped-key record.

## JNI/native boundary

Vodozemac does not provide the Android/Kotlin API shape Kenato needs as a stable Maven dependency. M3 therefore introduces a minimal Kenato-owned Rust `cdylib` JNI bridge.

The bridge is constrained to:

- account creation/restore/public-key/one-time-key operations;
- outbound/inbound Olm session creation;
- encrypt/decrypt;
- encrypted pickle import/export;
- bounded conversion of message type/ciphertext and public keys.

It must not:

- expose raw private engine keys;
- implement DH, KDF, ratchet, AEAD/MAC or signature primitives itself;
- enable vodozemac low-level/hazmat APIs;
- accept caller-selected cipher suites/session versions;
- log keys, pickles, ciphertext/plaintext or JNI byte arrays.

The Rust toolchain, Android NDK, supported ABIs and any build helper are pinned when this bridge lands. Cargo's lockfile is committed and CI must build/test the Rust crate plus Android native packaging before merge.

## Alternatives

### Signal libsignal

Upstream explicitly states that use outside Signal is unsupported and that its Java/Swift/TypeScript APIs and bridge layers may change without notice. Current upstream is licensed under GNU AGPLv3.

Kenato's ADR 0006 intentionally defers a permanent repository/product license. Selecting libsignal now would therefore combine an unsupported external API with a licensing decision that should not be made implicitly as a crypto implementation detail. It is not selected for M3.

References:

- <https://github.com/signalapp/libsignal>
- <https://github.com/signalapp/libsignal/blob/main/README.md>

### Legacy libolm

Not selected. The old C/C++ Olm implementation is deprecated in favor of vodozemac and upstream cites memory-safety/historical security concerns as a reason to migrate. A new Android integration should not begin on the deprecated native implementation.

### Kenato-written Double Ratchet

Rejected. Implementing the protocol ourselves would create exactly the unaudited cryptographic surface the repository rules prohibit.

## Follow-up checks before M3 completion

- exact vodozemac/Cargo dependency resolution reviewed and locked;
- Rust/JNI static and dynamic analysis in CI;
- Android ABI/load smoke tests;
- malformed/oversized JNI input tests;
- one-time-key exhaustion and duplicate-allocation tests;
- expected-peer Curve25519 identity mismatch tests;
- pre-key/normal message type validation;
- replay, duplicate, reordering, >40 skipped-key retention and >2000 gap behavior tests;
- crash/persistence tests proving state is committed before ciphertext/plaintext escapes;
- pickle-key non-reuse and Keystore-loss/corruption tests;
- dependency/license/security re-review before an engine upgrade.
