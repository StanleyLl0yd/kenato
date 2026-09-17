# Kenato

**Talk freely.**

Kenato is a privacy-first mobile app for private 1-to-1 voice calls and simple end-to-end encrypted messaging without phone numbers.

## Product principles

- No phone number or email required.
- Contacts are invite-only.
- Calls and messages are end-to-end encrypted.
- The server must never need plaintext user content or private identity keys.
- Lightweight client and minimal server architecture.
- Android first; iOS is planned after the Android protocol and calling experience are stable.
- RuStore first, Google Play later.

## Target stack

- Android: Kotlin + Jetpack Compose
- Media: WebRTC + Opus
- Server: Go
- Realtime signaling: WSS
- Server storage: SQLite
- NAT traversal / relay: ICE + STUN/TURN (coturn)
- Wire format: Protocol Buffers
- CI/CD: GitHub Actions

## Repository layout

```text
android/    Android application
branding/   Canonical brand assets and platform-derivative records
server/     Go backend
protocol/   Versioned wire protocol and test vectors
docs/       Architecture, security and ADRs
scripts/    Project tooling
```

**M0 — Foundation**, **M1 — Local Identity**, **M2 — Invite + Contact Establishment**, **M3 — E2EE Session**, and **M4 — Minimal Messaging** are complete. M4 implementation slices #50–#53 and final repository-wide end-to-end/security verification #54 completed with the final audit merged in #60 and closure status merged in #62; the resulting exact `main` revision was independently green.

M4 provides minimal E2EE text messaging on the reviewed M3 Double Ratchet boundary: bounded authenticated WSS routing, offline mailbox behavior, exact retry/ACK semantics, crash-safe Android message handoffs, and app-private bounded conversation history. It did not start WebRTC/calling work. **#59 / M4.5** is now the active next milestone: the first closed messaging-only `0.0.1` release and physical-device gate. Published pre-1.0 versions use ordinary numeric versions (`0.0.1`, `0.0.2`, ...), with no alpha/beta/rc suffixes. M5 remains blocked until #59 is complete.

## Security

Security and privacy are architectural constraints, not optional features. See [SECURITY.md](SECURITY.md) and [docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md).

## Brand

- Name: **Kenato**
- Direction: **Zen Minimal**
- Primary tagline: **Talk freely.**
- Product descriptor: **Private calls & messages**

## License

No open-source license has been selected yet. Until a license is added, no rights are granted to copy, modify, or redistribute the source code.
