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

- device-generated cryptographic identity;
- Android Keystore-backed long-lived key protection;
- signed prekey and one-time prekey lifecycle;
- local identity persistence and failure handling;
- deterministic protocol/crypto test vectors where applicable.

## M2 — Invite + Contact Establishment

- server identity public material/prekeys;
- single-use expiring invites;
- QR/deep-link flow;
- authenticated initial session establishment;
- local contact identity pinning;
- abuse/resource limits.

## M3 — E2EE Session

- reviewed asynchronous session establishment;
- Double Ratchet or equivalent mature reviewed protocol implementation;
- replay/reordering/duplicate behavior;
- bounded skipped-key handling;
- identity-change handling;
- persistence/restart tests.

## M4 — Minimal Messaging

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
