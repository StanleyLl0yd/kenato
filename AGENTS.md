# AGENTS.md

## Project

Kenato is a privacy-first mobile communication app focused on 1-to-1 voice calls and minimal end-to-end encrypted messaging.

## Core invariants

1. The server must never require plaintext user messages, call signaling content, or voice content.
2. Private identity keys never leave the device.
3. Contact identity must never change silently.
4. All untrusted inputs are bounded.
5. There is no public user search or enumeration.
6. Sensitive data and secrets must never be written to logs.
7. Prefer simple, auditable designs over feature-rich abstractions.
8. Do not implement custom cryptographic primitives when mature, reviewed primitives or protocols exist.

## Engineering rules

- Keep `main` buildable and releasable.
- Use short-lived branches and small pull requests.
- Every behavior change requires appropriate tests.
- Protocol changes require compatibility consideration and test vectors.
- Security-sensitive changes require explicit security impact notes.
- Avoid unnecessary dependencies.
- Do not introduce telemetry or analytics SDKs without an explicit decision.
- Do not add phone-number, email, address-book upload, public user search, groups, video, files, or multi-device support unless a milestone explicitly requires it.
- Do not commit signing keys, credentials, tokens, secrets, generated release artifacts, or local configuration.

## Architecture

Target repository structure:

```text
android/
server/
protocol/
deploy/
docs/
scripts/
```

Android is native Kotlin/Jetpack Compose. The server is Go. WebRTC owns media transport; coturn provides STUN/TURN fallback. SQLite is the initial server datastore.

## UI / brand

Brand: Kenato  
Visual direction: Zen Minimal  
Tagline: Talk freely.

Prefer calm, simple, spacious UI. Avoid security theatrics, visual clutter, neon/cyberpunk styling, or decorative Japanese clichés.

## Verification

Run the narrowest relevant checks first, then expand when needed. Before a release or full audit, perform repository-wide verification.
