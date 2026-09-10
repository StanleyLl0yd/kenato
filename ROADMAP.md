# Kenato Roadmap

Kenato is developed milestone-first. Scope expands only after the current milestone's exit criteria are satisfied.

## M0 — Foundation

Status: **Complete** (2026-09-09).

- repository structure and operating contract;
- Android and Go skeletons;
- versioned protocol foundation;
- CI/security/dependency baseline;
- release/signing conventions;
- architecture, threat model, brand, and ADR baseline.

Exit: buildable, testable foundation with security gates and no unresolved foundation inconsistency.

## M1 — Local Identity

Status: **Complete** (2026-09-10).

- device-generated cryptographic identity;
- Android Keystore-backed long-lived key protection;
- signed prekey and one-time prekey lifecycle;
- local identity persistence and failure handling;
- deterministic protocol/crypto test vectors where applicable.

Exit: device-local identity is persistent, bounded, fail-closed on corruption/key loss, backup-excluded, documented, and covered by required CI/security verification without introducing M2 server/contact behavior.

## M2 — Invite + Contact Establishment

Status: **Complete** (2026-09-10).

- bounded publication of authenticated public identity material and public prekeys;
- single-use 32-byte invites with fixed 24-hour expiry and SHA-256 hash-at-rest storage;
- canonical QR/deep-link invite representation and strict parsing;
- authenticated creator/redeemer contact-establishment proofs;
- local contact identity pinning with no silent replacement;
- bounded Android transport/state behavior and server abuse/resource limits;
- SQLite/WAL invite lifecycle persistence with explicit expired-record cleanup;
- malformed, duplicate, replay, expiry, identity-substitution and persistence regression coverage.

Exit: public identity/prekey publication and invite/contact establishment are authenticated, bounded, single-use/expiring, locally identity-pinned, persistence-safe, documented, and repository-wide verified without introducing the M3 ratchet/session protocol.

## M3 — E2EE Session

Status: **In progress** (started 2026-09-10).

- reviewed asynchronous session establishment rooted in the pinned M1/M2 Kenato identity;
- Apache-2.0 vodozemac Olm/Double Ratchet engine, exact-version pinned through the Android native boundary;
- authenticated P-256 binding of engine-specific Curve25519/Ed25519 account material and one-time keys;
- deterministic invite-redeemer initiator / invite-creator responder bootstrap;
- bounded one-time session-key allocation with no fallback-key downgrade;
- replay/reordering/duplicate behavior and the engine's bounded skipped-key handling;
- crash-safe fail-closed session/account persistence and restart tests;
- identity/session-account change handling;
- native/JNI, dependency and protocol security review.

Exit: a pinned contact can establish and persist a reviewed asynchronous ratcheted session, encrypt/decrypt bounded opaque application payloads with explicit replay/reordering behavior, survive restart without ratchet rollback, fail closed on identity/session-state corruption or replacement, and pass repository-wide exact-head/exact-main verification without introducing M4 routing/mailbox/product messaging behavior.

## M4 — Minimal Messaging

Status: **Not started**.

- WSS routing;
- online direct delivery;
- bounded offline mailbox;
- acknowledgements and retry semantics;
- local conversation history;
- server deletion after acknowledged delivery.

## M5 — Voice Core

- audio-only WebRTC;
- Opus;
- authenticated encrypted call signaling;
- ICE/STUN;
- P2P connectivity;
- coturn fallback;
- deterministic call state machine.

## M6 — Real Mobile Calling

- foreground/background call lifecycle;
- incoming-call notifications;
- lock-screen behavior;
- speaker/headset/Bluetooth routing;
- audio focus;
- Doze/power-management behavior;
- Wi-Fi/mobile-network transition handling;
- push wake-up abstraction.

## M7 — Reliability

- loss/latency/bandwidth simulation;
- TURN-only paths;
- reconnect behavior;
- server restart/recovery;
- SQLite recovery;
- performance, memory, network, and battery regression checks;
- representative physical-device testing.

## M8 — Security Hardening

- repository-wide security audit;
- protocol/crypto review;
- parser/resource fuzzing and malformed-input coverage;
- dependency/supply-chain review;
- Android backup/logging/permission review;
- server/turn abuse hardening;
- release signing review;
- no open Critical/High findings.

## M9 — Private Alpha

Small real-device cohort. Focus on call quality, OEM behavior, TURN usage, crashes, battery, invite UX, and update/install behavior.

No feature expansion beyond fixes required for alpha quality.

## M10 — Public Beta / Release Candidate

- UI/accessibility polish;
- RU + EN;
- store assets;
- privacy/support documentation;
- final compatibility and release verification.

## M11 — RuStore 1.0

Publish the same reviewed source commit as signed APK/AAB artifacts, with repository-wide release verification.

## M12 — Google Play

Adapt store configuration/policy requirements without forking product source or protocol behavior.

## Post-1.0

Possible work only after evidence of need:

- disappearing messages;
- stronger user-facing identity verification;
- iOS implementation and Android↔iOS interoperability;
- self-hosting improvements;
- multi-device research.

Groups, video, federation, and richer media are separate architecture milestones and are not implicit extensions of 1.0.
