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

Status: **Complete** (2026-09-13; tracker #31 and final verification #35 closed).

- reviewed asynchronous session establishment rooted in the pinned M1/M2 Kenato identity;
- Apache-2.0 vodozemac Olm/Double Ratchet engine, exact-version pinned through the Android native boundary;
- authenticated P-256 binding of engine-specific Curve25519/Ed25519 account material and one-time keys;
- deterministic invite-redeemer initiator / invite-creator responder bootstrap;
- bounded one-time session-key allocation with no fallback-key downgrade;
- exact persisted retry of the initial pre-key frame until successful submission is durably committed;
- replay/reordering/duplicate behavior and the engine's bounded skipped-key handling;
- crash-safe fail-closed account/session persistence with fresh Keystore-wrapped per-snapshot pickle keys;
- atomic inbound account-OTK consumption/session creation and explicit destructive-claim failure semantics;
- restart, corruption/key-loss, partial-write, cancellation, identity/account/OTK-substitution regression coverage;
- pinned Rust/JNI/NDK three-ABI Android build and dependency/protocol security review.

Exit: a pinned contact can establish and persist a reviewed asynchronous ratcheted session, encrypt/decrypt bounded opaque application payloads with explicit replay/reordering behavior, survive restart without ratchet rollback, fail closed on identity/session-state corruption or replacement, and pass repository-wide exact-head/exact-main verification without introducing M4 routing/mailbox/product messaging behavior.

Completion record: #32–#35 are complete, the final M3 PR was squash-merged to protected `main`, exact-main verification completed, and the expanded 11-context required-check baseline is active. M4 was not started as part of M3 and remains a separate milestone.

## M4 — Minimal Messaging

Status: **Complete** (2026-09-17; tracker #49; final verification #54).

- WSS routing;
- online direct delivery;
- bounded offline mailbox;
- acknowledgements and retry semantics;
- local conversation history;
- server deletion after acknowledged delivery.

Implementation slices: #50 protocol/auth/delivery contract — **complete**; #51 bounded mailbox persistence — **complete**; #52 authenticated WSS/direct routing — **complete**; #53 Android transport/history — **complete**; #54 final end-to-end/security verification — **complete**.

Exit: end-to-end minimal messaging is durable, bounded, identity-bound, restart/reconnect safe, reviewed across Android/server boundaries, and exact-main green with no unresolved Critical/High M4 finding.

Completion record: #50–#54 completed the M4 protocol/authentication, bounded mailbox, authenticated transport, Android durability/history, and final repository-wide security-review slices. Final audit PR #60 and closure PR #62 were squash-merged to protected `main`; exact `main` `7b85dd76d90416d3d2a8cf98a870f338fb1429b6` independently passed CI, Semgrep/Security, Gitleaks, and CodeQL for Go, Java/Kotlin, Rust, and Actions. M4 did not introduce M5/WebRTC work.

## M4.5 — Closed Messaging Release `0.0.x`

Status: **Active**; #59/M4.5 is the current release gate. M4 is complete. The signed `0.0.1` source release is published; #75/#76 adds the minimal application surface required to execute the physical-device gate as `0.0.2`. M5 remains blocked until this gate completes.

This is a small messaging-only pre-voice release, not a separate prerelease version class:

- first published source version `0.0.1`, Android `versionCode = 1`, immutable tag `v0.0.1`; follow-up M4.5 acceptance fixes advance numerically (`0.0.2` / `versionCode = 2`, then `0.0.3`, ...);
- signed Android APK/AAB built from the exact reviewed `main` commit;
- GitHub Release containing the verified APK/AAB/checksum;
- direct distribution to a small trusted cohort (initially roughly 2–10 testers; public store publication is not required);
- at least two physical Android devices;
- clean install and identity persistence;
- invite/contact establishment and M3 session bootstrap;
- online E2EE text and offline mailbox/reconnect delivery;
- duplicate/retry/ACK behavior without duplicate visible history;
- process death, relaunch and device reboot recovery;
- establish `0.0.1` as the update baseline; from `0.0.2` onward verify in-place update preserving identity/session/history;
- Wi-Fi/mobile-network loss and recovery;
- no third-party analytics/crash SDK or plaintext diagnostics added merely for testing.

Versioning policy: published pre-1.0 builds use ordinary numeric versions (`0.0.1`, `0.0.2`, ...). Alpha, beta, rc, and other prerelease suffixes are not used.

Exit: `0.0.1` remains the immutable signed baseline; the acceptance-capable numeric follow-up (`0.0.2` or later if blocker fixes are required) is installed on the closed cohort and the full #59 flow is exercised. Blockers are recorded and fixed without unrelated feature expansion. **M5 must not start until #59 is complete.**

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

## M9 — Private Device Test

Small real-device cohort. Focus on call quality, OEM behavior, TURN usage, crashes, battery, invite UX, and update/install behavior.

No feature expansion beyond fixes required for test quality.

## M10 — Public Test / Release Preparation

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
