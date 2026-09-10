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
  |- transient WebSocket routing
  |- bounded offline mailbox
  |- temporary TURN credentials
  |
  +-- SQLite

Voice media:
Android <---- WebRTC / ICE ----> Android
                  |
                  +---- coturn fallback
```

Only the identity/invite portion of that diagram is implemented through M2. Session cryptography, WebSocket routing, offline messaging, TURN credentials and calling remain later milestones.

## Client

Planned Android stack:

- Kotlin
- Jetpack Compose
- Coroutines / Flow
- Android Keystore
- local SQLite/Room as needed
- WebRTC
- Opus
- WSS transport

Client architecture keeps UI separate from call/media/session state. In particular, UI must not directly own or manipulate WebRTC `PeerConnection` objects.

Suggested boundaries:

```text
UI
 |
Application / use cases
 |
Domain
 |
Infrastructure
   |- Identity
   |- Crypto/session
   |- Signaling
   |- WebRtcTransport
   |- AudioSession
   |- Persistence
```

M1 implements the device-local identity boundary. M2 adds the Android contact-establishment boundary: canonical invite URI/QR payload handling, authenticated identity publication, invite create/redeem/claim transport, persistent pending-invite state and fail-closed peer identity pins. Private identity and prekey keys remain inside the M1 local security boundary.

## Server

Current server:

- Go single-service binary: `kenato-server`;
- SQLite/WAL persistence;
- bounded HTTP/Protocol Buffers M2 identity/invite API;
- authenticated public identity and prekey publication;
- single-use expiring invite lifecycle with token hashes at rest;
- periodic expired-invite retention cleanup plus cleanup at process start;
- no public identity lookup/search endpoint;
- loopback listener by default;
- intended systemd deployment behind a reviewed TLS-terminating reverse proxy.

Later milestones add WebSocket routing, bounded mailbox behavior and TURN credential issuance. No Redis, message broker, Kubernetes, or microservice split is planned for the initial architecture.

## Protocol

The wire protocol is versioned independently of implementation language.

Serialization is Protocol Buffers. M2 canonical signature payloads are defined independently of protobuf serialization so unknown-field handling and implementation language cannot alter signature bytes.

Transport-level metadata must contain only fields required for routing and protocol evolution. Message type and user content should remain inside authenticated ciphertext whenever the server does not require them.

## Identity and contact discovery

- Identity is generated on-device.
- No phone number or email is required.
- No public user search exists.
- New contacts are established only by an invite.
- M2 invite tokens are 32 random bytes, single-use, expire after 24 hours, and are represented at rest on the server only by SHA-256 hashes.
- Creator and redeemer prove their respective invite/contact actions with long-lived identity signatures.
- Contact identity keys are pinned locally and must not silently change.
- M2 deliberately stops before DH session establishment, one-time-prekey consumption and Double Ratchet state; those belong to M3.

## Messaging

The server acts as a bounded store-and-forward relay in the planned messaging architecture.

When a recipient is online, encrypted payloads should be forwarded directly without durable mailbox storage.

When offline, opaque payloads may be stored with strict limits and expiry. Initial design target:

- TTL: 72 hours;
- maximum encrypted envelope: 96 KiB;
- maximum queued messages per recipient: 500;
- delete immediately after acknowledged delivery.

These values are design targets for later milestones and are not M2 implementation claims.

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
3. device private identity keys do not leave the device;
4. remote contact identity cannot silently change;
5. untrusted inputs are bounded;
6. no public user enumeration;
7. no plaintext user content or secrets in logs.

## Deployment

The current non-production development host is an Oracle Cloud Infrastructure Ampere A1 ARM64 instance in Germany Central (Frankfurt), documented in `docs/development/OCI_HOST.md`.

The architecture remains provider-neutral: a small Linux VPS/free-tier instance and Raspberry Pi remain valid deployment targets, so backend resource usage should stay modest and dependencies minimal.

M0, M1 and M2 are complete. M3 has not started. Public server exposure still waits for an explicitly reviewed deployment/TLS boundary.

Self-hosted federation is explicitly out of scope for 1.0.
