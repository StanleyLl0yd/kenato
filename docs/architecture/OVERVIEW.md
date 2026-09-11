# Architecture Overview

## Product boundary

Kenato is an Android-first, privacy-first communication app for:

- 1-to-1 voice calls;
- minimal end-to-end encrypted text messaging;
- invite-only contact establishment.

The first stable release intentionally excludes public user discovery, phone numbers, email accounts, groups, video, files, cloud history, and multi-device synchronization.

## High-level architecture

```text
Android client
  |
  | HTTPS / WSS (opaque encrypted payloads)
  v
kenato-server (Go)
  |- identity public material / prekeys
  |- invite lifecycle
  |- M3 public session bootstrap / temporary init state
  |- transient WebSocket routing          [M4]
  |- bounded offline mailbox              [M4]
  |- temporary TURN credentials           [later]
  |
  +-- SQLite

Voice media:
Android <---- WebRTC / ICE ----> Android
                  |
                  +---- coturn fallback
```

Through the current M3 work, identity/contact establishment and the asynchronous E2EE session/bootstrap boundary are implemented. Ordinary encrypted-message routing/mailbox behavior, TURN credentials, and calling remain later milestones.

## Client

Android stack in the current architecture:

- Kotlin / Jetpack Compose;
- Android Keystore;
- vodozemac 0.10.0 Olm behind a Kenato-owned Rust/JNI boundary;
- app-private atomic session persistence;
- Coroutines / Flow where asynchronous application integration requires them;
- later WebRTC / Opus / WSS transport layers.

Client architecture keeps UI separate from identity, contact, crypto/session, transport, and media state. UI must not own private crypto state or directly manipulate later WebRTC `PeerConnection` objects.

```text
UI
 |
Application / use cases
 |
Domain
 |
Infrastructure
   |- Identity / contacts
   |- Crypto/session
   |- Signaling              [later]
   |- WebRtcTransport        [later]
   |- AudioSession           [later]
   |- Persistence
```

M1 implements the device-local P-256 identity boundary. M2 adds canonical invite URI/QR handling, authenticated identity publication, invite create/redeem/claim transport, persistent pending-invite state, and fail-closed peer identity pins.

M3 retains that P-256 identity as the sole contact trust anchor and adds a persistent vodozemac Olm account/session boundary. Engine-specific Ed25519/Curve25519 account material and OTKs are authenticated by the existing P-256 identity. The invite redeemer deterministically creates the outbound session and the invite creator accepts the matching inbound session only after M2/M3 provenance, exact local OTK provenance, and the decrypted canonical control payload are verified.

Account/session snapshots use fresh per-mutation pickle keys whose wrapping keys are protected by Android Keystore. State advances are durably committed before ciphertext/plaintext escapes, and account OTK consumption plus inbound-session creation are one atomic M3 state update. Session state is app-private and backup/device-transfer excluded.

## Server

Current server through M3:

- Go single-service binary: `kenato-server`;
- SQLite/WAL persistence;
- bounded HTTP/Protocol Buffers M2 identity/invite API;
- authenticated public identity and prekey publication;
- single-use expiring invite lifecycle with token hashes at rest;
- authenticated M3 public Olm-account publication and bounded OTK allocation;
- temporary invite-bound M3 reservation/init state only;
- destructive creator claim with transactional cleanup of temporary relationship/bootstrap state;
- periodic expired-invite retention cleanup plus cleanup at process start;
- no public identity/session lookup or search endpoint;
- loopback listener by default;
- intended deployment behind a reviewed TLS-terminating reverse proxy.

The server never receives private P-256, prekey, Olm account/session, or ratchet keys and does not decrypt the initial Olm frame. Later milestones add WebSocket routing, bounded mailbox behavior, and TURN credential issuance. No Redis, message broker, Kubernetes, or microservice split is planned for the initial architecture.

## Protocol

The wire protocol is versioned independently of implementation language and serialized with Protocol Buffers.

M2 and M3 canonical signature/control payloads are defined independently of protobuf serialization so unknown-field handling and implementation language cannot alter authenticated bytes. M3 bootstrap signatures bind the existing Kenato identity to the exact Olm account generation, account identity keys, publication revision, and OTK set. Reservation, submit, claim, and decrypted init-control checks bind the exact invite participants and session provenance.

Transport-level metadata contains only fields required for routing and protocol evolution. Ordinary message type and user content remain inside authenticated ciphertext whenever the server does not require them.

## Identity and contact discovery

- Identity is generated on-device.
- No phone number or email is required.
- No public user search exists.
- New contacts are established only by an invite.
- M2 invite tokens are 32 random bytes, single-use, expire after 24 hours, and are represented at rest on the server only by SHA-256 hashes.
- Creator and redeemer prove their invite/contact actions with long-lived P-256 identity signatures.
- Contact identity keys are pinned locally and must not silently change.
- M3 engine identity material is authenticated under that pin and unexpected account/key replacement fails closed.
- M3 uses bounded Curve25519 one-time keys with no fallback-key downgrade.

## E2EE session boundary

M3 uses exact-pinned vodozemac 0.10.0 Olm/Double Ratchet through a minimal Rust/JNI bridge. It provides only the crypto/session primitive needed by later application layers:

- create/restore the local Olm account;
- publish/replenish bounded authenticated public OTK state;
- create/accept the deterministic first session for a pinned contact;
- encrypt/decrypt bounded opaque application payloads;
- persist/restart ratchet state without returning data before the advanced state is committed.

The local protocol hard maximum is 50 tracked OTKs, 256 persisted contact sessions, 64 KiB application plaintext, and 96 KiB Olm frames. Vodozemac's own fixed skipped-message-key/message-gap bounds are not widened by Kenato.

M3 does **not** provide conversation history, online/offline delivery, acknowledgements, WSS routing, or mailbox semantics. Those are M4.

## Messaging

The server acts as a bounded store-and-forward relay only in the planned M4 messaging architecture.

When a recipient is online, encrypted payloads should be forwarded directly without durable mailbox storage. When offline, opaque payloads may be stored with strict limits and expiry. Initial design target:

- TTL: 72 hours;
- maximum encrypted envelope: 96 KiB;
- maximum queued messages per recipient: 500;
- delete immediately after acknowledged delivery.

These values are later-milestone design targets, not current M3 implementation claims.

## Calling

Voice is audio-only for 1.0.

Planned media stack:

- WebRTC;
- Opus;
- ICE/STUN;
- P2P when possible;
- coturn relay when direct connectivity fails.

TURN is a packet relay, not a media server. It must not require plaintext voice content.

## Security invariants

See the threat model for detail. Architecture changes must preserve:

1. server cannot decrypt message content;
2. server cannot decrypt voice content;
3. device private identity/session keys do not leave the device;
4. remote contact identity cannot silently change;
5. engine account/session replacement cannot silently bypass the pinned Kenato identity;
6. ratchet state cannot be exposed to callers before required durable state advancement;
7. untrusted inputs and retained state are bounded;
8. no public user enumeration;
9. no plaintext user content or secrets in logs.

## Deployment

The current non-production development host is an Oracle Cloud Infrastructure Ampere A1 ARM64 instance in Germany Central (Frankfurt), documented in `docs/development/OCI_HOST.md`.

The architecture remains provider-neutral: a small Linux VPS/free-tier instance and Raspberry Pi remain valid deployment targets, so backend resource usage should stay modest and dependencies minimal.

M0, M1, and M2 are complete. M3 implementation is in final PR verification; M3 is not complete until #34 is merged and the repository-wide #35 audit/verification succeeds on exact `main`. M4 has not started. Public server exposure still waits for an explicitly reviewed deployment/TLS boundary.

Self-hosted federation is explicitly out of scope for 1.0.
