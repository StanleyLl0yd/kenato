# M3 Session Engine Review

Status: implementation review for M3 Android/native session boundary  
Date: 2026-09-11

This review records both the dependency/security decision behind ADR 0009 and the Android/native implementation now present in M3 PR #40. M3 is not considered complete until #34 is merged and the separate repository-wide #35 verification is finished on exact `main`.

## Requirements

The M3 engine must provide a mature asynchronous one-to-one Double Ratchet implementation while preserving these Kenato constraints:

- the M1/M2 ECDSA P-256 identity remains the contact trust anchor;
- no private identity/session key is sent to the server;
- no home-grown ratchet or ad-hoc cryptographic construction;
- bounded out-of-order/skipped-key state;
- serializable state for crash-safe Android persistence;
- no silent downgrade or identity replacement;
- dependency licensing compatible with ADR 0006 without making an implicit repository-license decision;
- Android support is reproducibly buildable and security-reviewed.

## Selected: vodozemac 0.10.0 / Olm

Upstream release: <https://github.com/matrix-org/vodozemac/releases/tag/0.10.0>

Selected properties verified against the tagged upstream source:

- package version: exact `0.10.0`;
- license: `Apache-2.0`;
- minimum Rust version: `1.85`;
- implementation language: Rust;
- Kenato uses only the one-to-one `olm` account/session API and `SessionConfig::version_1()`;
- the account exposes persistent Ed25519 and Curve25519 public identity keys plus Curve25519 one-time keys;
- outbound session creation performs the engine's 3DH using the recipient Curve25519 identity key and one-time key;
- inbound session creation requires the caller-supplied expected sender Curve25519 identity key and rejects a mismatched pre-key message identity;
- the account removes the matching private one-time key as part of successful inbound-session creation;
- Olm ciphertext has an explicit pre-key/normal message type and bounded binary encoding suitable for Kenato-owned envelopes;
- upstream documents an independent Least Authority audit with no significant findings.

The tagged implementation also has hard internal out-of-order bounds:

- `MAX_MESSAGE_KEYS = 40` retained skipped message keys;
- `MAX_MESSAGE_GAP = 2000`, after which decryption rejects the gap rather than deriving/storing an unbounded chain.

Kenato does not expose an API that changes those constants or low-level message-key derivation.

## Implemented dependency and native boundary

PR #40 exact-pins the native dependency and build boundary:

- `vodozemac = =0.10.0`, with the reviewed feature surface;
- Rust `1.85.0` for both native crates;
- committed Cargo lockfiles for `native/session-engine` and `native/session-jni`;
- Android NDK `28.2.13676358`;
- `cargo-ndk 4.1.2`;
- Android API 26 native target;
- `armeabi-v7a`, `arm64-v8a`, and `x86_64` JNI libraries.

The Kenato-owned JNI crate is deliberately narrow. It exposes the reviewed account/session operations needed by Kotlin and delegates cryptography to vodozemac. It does not implement DH, KDF, ratchet, AEAD/MAC, signatures, or caller-selected cipher suites. Native/JNI inputs and outputs are bounded and private engine key material is not exposed as an application API.

CI and Android release workflows build the pinned native libraries before Gradle packaging and verify that the expected three ABI libraries, and no unexpected `.so` entries, are present. The repository security baseline pins and checks the same Rust/NDK/cargo-ndk/API/ABI contract so workflow drift fails closed.

## Persistence implementation

Vodozemac's encrypted pickle helper derives its pickle cipher IV deterministically from the caller-provided pickle key. Reusing one pickle key across changing snapshots is therefore unacceptable for Kenato state persistence.

The Android repository uses a **fresh cryptographically random 32-byte pickle key for every account/session snapshot mutation**. Each pickle key is wrapped with a non-exportable Android Keystore AES-GCM key and stored only with the corresponding encrypted pickle. Snapshot wrapping is context-bound with Kenato AAD, and ordinary in-process pickle-key buffers are zeroed when practical.

M3 state is app-private and backup/device-transfer excluded. Persisted state is bounded and self-validating, and Android Keystore/state loss or mismatch fails closed instead of silently regenerating the Olm account.

Crash-sensitive ordering is part of the security contract:

- outbound encryption persists the advanced session snapshot before ciphertext is returned;
- inbound decryption persists the advanced session snapshot before plaintext is returned;
- inbound-session creation persists the consumed account OTK and new session together in one atomic M3 state write before plaintext escapes;
- outbound bootstrap persists the exact pre-key frame before submit and retains it across failed submit/restart until the successful submit is durably cleared;
- cancellation is not honored between a successful submit and that durable pending-frame clear;
- after a destructive creator claim, cancellation is not honored until the response is verified and the required local commit sequence finishes or fails.

The destructive creator-claim boundary spans two local stores that cannot be transacted together. The authenticated M2 contact pin is committed first and the atomic M3 inbound state second. An M2 commit failure leaves M3 state and the local OTK untouched. An M3 commit failure may leave the valid M2 pin, but no M3 session is persisted and the OTK remains unconsumed; because the server claim is destructive, recovery requires a fresh invite. Reversing the order is rejected because it could leave a durable M3 session without its M2 trust anchor.

## One-time-key and state bounds

Kenato uses no Olm fallback key in M3. The normal local target is 32 OTKs and the protocol/runtime/persisted-state hard maximum is one shared `SESSION_MAX_ONE_TIME_KEYS = 50` bound. OTK bookkeeping ids are positive/monotonic and duplicate public-key material is compared by exact bytes rather than hash codes.

Other local bounds include 256 persisted sessions, 64 KiB application plaintext, 96 KiB Olm frames, fixed 32-byte public Olm keys, and bounded serialized account/session snapshots. Native vodozemac skipped-key/message-gap bounds remain unchanged.

## Identity and bootstrap verification

The M1/M2 P-256 identity is still the sole contact trust anchor. M3 account identity keys, account generation, publication revision, and OTK set are authenticated by the owner's P-256 binding signature. The deterministic invite redeemer is the initiator and the invite creator is the responder.

The responder re-verifies the returned M2 redemption material, redeemer M3 binding, submit proof, local creator account generation, and exact creator OTK id/public bytes before accepting the inbound session. The decrypted control plaintext is also compared against canonical context binding both peers, invite, account generations, and creator OTK provenance. Unexpected identity/account/key replacement fails closed.

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

## Verification state

PR #40 contains Rust engine/JNI tests plus Android protocol, persistence, corruption/key-loss, restart, atomicity, pending-init recovery, cancellation, substitution, and lifecycle regression coverage. CI also exercises pinned native builds for all three Android ABIs before Android lint/test/build packaging.

The implementation is still subject to exact-head PR gates and then #35's literal repository-wide audit/refactor and exact-main verification. Any finding from those gates or the final audit must be fixed before M3 is marked complete. M4 remains out of scope.
