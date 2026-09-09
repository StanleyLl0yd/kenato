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

Client architecture should keep UI separate from call/media/session state. In particular, UI must not directly own or manipulate WebRTC `PeerConnection` objects.

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

## Server

Initial server:

- Go
- single service binary: `kenato-server`
- SQLite/WAL
- WebSocket + HTTPS
- systemd deployment
- coturn as a separate service
- loopback listener by default; public deployment must explicitly expose it behind the reviewed TLS boundary

No Redis, message broker, Kubernetes, or microservice split is planned for the initial architecture.

## Protocol

The wire protocol is versioned independently of implementation language.

Planned serialization: Protocol Buffers.

Transport-level metadata must contain only fields required for routing and protocol evolution. Message type and user content should remain inside authenticated ciphertext whenever the server does not require them.

## Identity and contact discovery

- Identity is generated on-device.
- No phone number or email is required.
- No public user search exists.
- New contacts are established only by an invite.
- Contact identity keys are pinned locally and must not silently change.

## Messaging

The server acts as a bounded store-and-forward relay.

When a recipient is online, encrypted payloads should be forwarded directly without durable mailbox storage.

When offline, opaque payloads may be stored with strict limits and expiry. Initial design target:

- TTL: 72 hours;
- maximum encrypted envelope: 96 KiB;
- maximum queued messages per recipient: 500;
- delete immediately after acknowledged delivery.

These values are design targets and must be validated by implementation and load testing.

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

Initial deployment target is a small Linux VPS or free-tier cloud instance. Raspberry Pi remains a valid self-hosted deployment target, so backend resource usage should remain modest and dependencies minimal.

Self-hosted federation is explicitly out of scope for 1.0.
