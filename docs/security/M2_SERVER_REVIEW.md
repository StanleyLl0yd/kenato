# M2 Server Security Review

Status: server implementation and final M2 hardening reviewed 2026-09-10.

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
- Expired invite rows are removed opportunistically during invite operations and by explicit retention cleanup at process startup and every hour, so inaccessible expired relationship metadata does not depend on future user activity for eventual deletion.

## Network/API boundary

- The process binds to loopback by default; public exposure is not part of M2.
- M2 uses four explicit POST routes and exposes no public identity enumeration/lookup route.
- Request bodies and protobuf fields are bounded before expensive cryptographic work.
- Duplicate singular protobuf fields and malformed framing fail closed; unknown supported wire fields remain forward-compatible.
- Unsupported protocol versions fail explicitly.
- Contact endpoints require protobuf media types and emit `Cache-Control: no-store` plus `X-Content-Type-Options: nosniff`.
- Expensive verification is protected by a process-wide bounded concurrency/rate gate before service cryptography.
- Missing creator identity and malformed/unauthenticated contact requests share the same generic public invalid-request response category rather than exposing a dedicated identity-existence response.
- HTTP error responses do not expose database paths, raw cryptographic diagnostics or request secrets.
- HTTP server header, read, write and idle timeouts remain explicit, and contact service operations receive a bounded request context.

The M2 process-wide gate is a resource bound, not a complete source-aware public-edge rate limiter. Source-aware/distributed controls must be designed at the reviewed TLS/reverse-proxy boundary rather than trusting arbitrary forwarded-address headers in the loopback service.

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
- four concurrent expensive contact operations and a bounded global minute window;
- bounded HTTP headers and request/service timeouts;
- explicit periodic removal of expired invite rows.

These are defensive M2 limits, not public-service scaling guarantees. Load-derived tuning and source-aware edge controls belong to later deployment/reliability work.

## Retry and retention semantics

- Identity publication is idempotent only for the exact already accepted revision/material combination.
- Invite creation is idempotent for the same still-active creator/token record and does not extend the original expiry.
- Redemption replay by the same redeemer identity returns the original redemption timestamp; a different redeemer is rejected.
- Creator claim is intentionally one-shot. After a successful claim the relationship row is deleted; an HTTP response lost after server commit cannot be replayed from retained server state. The creator must establish a fresh invite. This is an explicit availability/privacy trade-off, not silent retry behavior.

## Verification evidence

M2 verification includes repository CI (`go mod tidy` lock verification, formatting, unit tests, race tests, `go vet`, `govulncheck`, linux/amd64 and linux/arm64 server builds, Android verification and protocol syntax) together with Semgrep/Security and Quality, Gitleaks, Dependency Review and CodeQL on the final review head. The milestone exit additionally requires the squash-merged exact `main` commit to pass its applicable post-merge checks.

## Explicit exclusions

M2 does not implement or imply one-time-prekey consumption, Diffie-Hellman session derivation, Double Ratchet state, encrypted messaging, mailbox behavior, WebSocket routing or TURN credentials. Those remain later milestones.
