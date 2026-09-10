# M2 Server Security Review

Status: server implementation reviewed 2026-09-10.

This note records the server-side security properties that must remain true for the M2 invite/contact backend. It supplements ADR 0008 and the project threat model; it does not define M3 session cryptography.

## Persistence

- SQLite stores only authenticated public identity/prekey bundles and minimum invite lifecycle metadata.
- Raw 32-byte invite tokens are never persisted; only SHA-256 token hashes are stored.
- The database uses WAL, foreign keys, synchronous FULL and defensive/DQS settings.
- The database path must resolve to a regular file; symlinks/non-regular paths are rejected and the main database file is mode 0600.
- Publication revisions are monotonic; exact canonical-payload replay at the accepted revision is idempotent, while changed same-revision and older publications fail closed.
- Invite redemption and redeemer publication are committed atomically.
- Expired records are not redeemable or claimable at the exact expiry boundary.
- A successful creator claim deletes the invite row in the same transaction after copying the bounded response data, so the temporary creator/redeemer relationship and redemption proof are not retained after claim. A repeated claim therefore fails as not found rather than extending server-side relationship retention.

## Network/API boundary

- The process binds to loopback by default; public exposure is not part of this change.
- M2 uses four explicit POST routes and exposes no public identity enumeration/lookup route.
- Request bodies and protobuf fields are bounded before expensive cryptographic work.
- Duplicate singular protobuf fields and malformed framing fail closed; unknown fields remain forward-compatible.
- Unsupported protocol versions fail explicitly.
- Contact endpoints require protobuf media types and emit `Cache-Control: no-store` plus `X-Content-Type-Options: nosniff`.
- Expensive verification is protected by a global bounded concurrency/rate gate before service cryptography.
- HTTP error responses use stable generic categories and do not expose database paths, raw cryptographic diagnostics or request secrets.

## Cryptographic binding

- Identity ids are SHA-256 of the exact canonical X.509 SubjectPublicKeyInfo bytes.
- Identity and prekey public keys must be canonical ECDSA P-256 keys.
- M1 signed-prekey signatures are verified before publication acceptance.
- M2 publication signatures bind the positive publication revision and complete ordered public prekey set.
- Invite, redemption and claim proofs use distinct domain-separated canonical payloads.
- A creator cannot redeem its own invite.
- One-time prekey ids are strictly increasing and may not reuse the signed-prekey id.

## Resource limits

Current implementation bounds include:

- 64 KiB wire messages;
- at most 100 one-time prekeys per published bundle;
- public key/signature byte limits before parsing/verification;
- at most 16 active invites per creator identity;
- bounded total identity and invite rows;
- four concurrent expensive contact operations and a bounded global minute window.

These are defensive M2 limits, not public-service scaling guarantees. Load-derived tuning belongs to later reliability work.

## Verification evidence

The reviewed implementation passed the exact-head CI suite including `go mod tidy` lock verification, formatting, unit tests, race tests, `go vet`, `govulncheck`, linux/amd64 build, `CGO_ENABLED=0` linux/arm64 build, Android verification and protocol syntax. The same exact head also passed Semgrep/Security and Quality, Gitleaks, Dependency Review and CodeQL before the final clean-history verification cycle.

## Explicit exclusions

M2 does not implement or imply one-time-prekey consumption, Diffie-Hellman session derivation, Double Ratchet state, encrypted messaging, mailbox behavior, WebSocket routing or TURN credentials. Those remain later milestones.
