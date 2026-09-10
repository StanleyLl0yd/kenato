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

**M0 — Foundation**, **M1 — Local Identity**, and **M2 — Invite + Contact Establishment** are complete. **M3 — E2EE Session** is in progress. **M4 — Minimal Messaging** has not started.

M3 is adding a reviewed asynchronous one-to-one Double Ratchet session boundary rooted in the already-pinned Kenato identity. ADR 0009 selects Apache-2.0 `vodozemac` Olm as the session engine and keeps the M1/M2 P-256 identity as the trust anchor. M3 deliberately stops before WebSocket routing, offline mailbox behavior, conversation history, or other M4 messaging features.

## Security

Security and privacy are architectural constraints, not optional features. See [SECURITY.md](SECURITY.md) and [docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md).

## Brand

- Name: **Kenato**
- Direction: **Zen Minimal**
- Primary tagline: **Talk freely.**
- Product descriptor: **Private calls & messages**

## License

No open-source license has been selected yet. Until a license is added, no rights are granted to copy, modify, or redistribute the source code.
