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

**M0 — Foundation** and **M1 — Local Identity** are complete. **M2 — Invite + Contact Establishment** is the next planned milestone and has not started.

## Security

Security and privacy are architectural constraints, not optional features. See [SECURITY.md](SECURITY.md) and [docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md).

## Brand

- Name: **Kenato**
- Direction: **Zen Minimal**
- Primary tagline: **Talk freely.**
- Product descriptor: **Private calls & messages**

## License

No open-source license has been selected yet. Until a license is added, no rights are granted to copy, modify, or redistribute the source code.
