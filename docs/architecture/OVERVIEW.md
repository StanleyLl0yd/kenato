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
  |- authenticated WSS routing            [M4 #52]
  |- bounded offline mailbox              [M4 #51]
  |- temporary TURN credentials           [later]
  |
  +-- SQLite contact/session state
  +-- SQLite mailbox state

Voice media:
Android <---- WebRTC / ICE ----> Android
                  |
                  +---- coturn fallback
```

M0–M3 are complete. M4 is active. #50 completed the authenticated messaging wire contract and shared protocol bounds. #51 completed the bounded durable mailbox. The current #52 slice implements authenticated WSS connection ownership, direct delivery and bounded mailbox fallback; Android local history and final M4 verification remain #53–#54. TURN credentials and calling remain later milestones.

## Client

Android stack in the current architecture:

- Kotlin / Jetpack Compose;
- Android Keystore;
- vodozemac 0.10.0 Olm behind a Kenato-owned Rust/JNI boundary;
- app-private atomic identity/contact/session persistence;
- Coroutines / Flow where asynchronous application integration requires them;
- M4 messaging transport/history layers as the milestone is implemented;
- later WebRTC / Opus media layers.

Client architecture keeps UI separate from identity, contact, crypto/session, messaging transport/history, and media state. UI must not own private crypto state or directly manipulate later WebRTC `PeerConnection` objects.

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
   |- Messaging transport/history    [M4]
   |- WebRtcTransport                 [later]
   |- AudioSession                    [later]
   |- Persistence
```

M1 implements the device-local P-256 identity boundary. M2 adds canonical invite URI/QR handling, authenticated identity publication, invite create/redeem/claim transport, persistent pending-invite state, and fail-closed peer identity pins.

M3 retains that P-256 identity as the sole contact trust anchor and adds a persistent vodozemac Olm account/session boundary. Engine-specific Ed25519/Curve25519 account material and OTKs are authenticated by the existing P-256 identity. The invite redeemer deterministically creates the outbound session and the invite creator accepts the matching inbound session only after M2/M3 provenance, exact local OTK provenance, and the decrypted canonical control payload are verified.

Account/session snapshots use fresh per-mutation pickle keys whose wrapping keys are protected by Android Keystore. State advances are durably committed before ciphertext/plaintext escapes, and account OTK consumption plus inbound-session creation are one atomic M3 state update. Session state is app-private and backup/device-transfer excluded. The JNI boundary minimizes native plaintext lifetime by zeroizing temporary Java→Rust plaintext copies and decrypted/inbound plaintext buffers after response transfer.

M4 does not weaken or replace that boundary. User text is serialized into a bounded M4 plaintext record and then encrypted by the established M3 session. The recipient validates the decrypted inner sender/recipient/message-id/expiry against the outer routing envelope before accepting the message.

A later M4 Android slice must add a crash-safe durable delivery handoff between successful M3 decrypt/ratchet commit and network ACK. ACKing immediately after decrypt is forbidden because a process crash before local history persistence could otherwise lose the plaintext while a redelivered ciphertext is correctly rejected by the already-advanced ratchet as a replay.

## Server

Current server foundation:

- Go single-service binary: `kenato-server`;
- SQLite/WAL persistence;
- bounded HTTP/Protocol Buffers M2 identity/invite API;
- authenticated public identity and prekey publication;
- single-use expiring invite lifecycle with token hashes at rest;
- authenticated M3 public Olm-account publication and bounded OTK allocation;
- temporary invite-bound M3 reservation/init state only;
- destructive creator claim with transactional cleanup of temporary relationship/bootstrap state;
- a separate bounded M4 mailbox SQLite/WAL database for opaque encrypted envelopes;
- authenticated M4 WSS routing with bounded connection/queue/pending-direct state;
- periodic expired-invite and mailbox retention cleanup plus bounded cleanup at process start;
- no public identity/session/mailbox/presence lookup or search endpoint;
- loopback listener by default;
- intended deployment behind a reviewed TLS-terminating reverse proxy.

M4 WSS connections authenticate ownership of an already-published Kenato identity using a random 32-byte, single-use, short-lived challenge signed by the existing P-256 identity. An identity id in a URL, query parameter, envelope, or first frame is never authentication. The server permits only bounded binary application frames, disables WebSocket compression and replaces an existing same-identity peer only after the new proof succeeds.

The server never receives private P-256, prekey, Olm account/session, or ratchet keys and never decrypts ordinary message content. The #51 mailbox retains only bounded routing identifiers, random message ids, acceptance/expiry timing, ciphertext-size metadata and the canonical opaque encrypted envelope. Recipient existence is resolved only through an internal contact-store interface; no lookup endpoint is added.

The mailbox has an independent schema/version lifecycle from the M2/M3 contact/bootstrap database. This prevents ACK/expiry retention behavior from coupling to destructive invite/bootstrap cleanup while preserving the same local durability posture: regular mode-0600 database files, WAL, synchronous `FULL`, bounded transactions, and fail-closed schema versions.

No Redis, message broker, Kubernetes, or microservice split is planned for the initial architecture.

## Protocol

The wire protocol is versioned independently of implementation language and serialized with Protocol Buffers.

M2/M3/M4 canonical signature/control payloads are defined independently of protobuf serialization so unknown-field handling and implementation language cannot alter authenticated bytes. M3 bootstrap signatures bind the existing Kenato identity to exact Olm account/session provenance. M4 WSS authentication reuses the same P-256 trust root with domain-separated canonical framing.

Transport-level metadata contains only fields required for routing and protocol evolution. Ordinary message text and semantic application content remain inside authenticated ciphertext whenever the server does not require them.

M4 intentionally duplicates sender identity, recipient identity, message id, and expiry inside the encrypted application plaintext. The receiver must compare those authenticated inner values with the outer routing envelope after decrypt. A malicious relay can still drop, delay, reorder, duplicate, or retain traffic, but cannot silently relabel a correctly validated message without causing a mismatch or M3 authentication failure.

The mailbox does not trust caller-supplied raw protobuf bytes separately from validated routing fields. It canonically encodes the validated envelope before persistence. Readback decodes and canonically re-encodes the retained envelope and cross-checks its sender, recipient, message id, expiry and ciphertext length against indexed row metadata before a delivery is returned.

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
- M4 transport authentication proves possession of the same long-lived P-256 identity; routing ids are not credentials.

## E2EE session boundary

M3 uses exact-pinned vodozemac 0.10.0 Olm/Double Ratchet through a minimal Rust/JNI bridge. It provides the crypto/session primitive used by M4:

- create/restore the local Olm account;
- publish/replenish bounded authenticated public OTK state;
- create/accept the deterministic first session for a pinned contact;
- encrypt/decrypt bounded opaque application payloads;
- persist/restart ratchet state without returning data before the advanced state is committed.

The M3 local hard maximum is 50 tracked OTKs, 256 persisted contact sessions, 64 KiB application plaintext, and 96 KiB Olm frames. Vodozemac's own fixed skipped-message-key/message-gap bounds are not widened by Kenato.

## Messaging

The M4 protocol uses one authenticated WSS identity context per connection. The server sends a 32-byte random challenge valid for at most 30 seconds; the client signs the canonical `KENATO-MESSAGING-AUTH-V1` payload with its existing P-256 identity key. Only after successful verification may the connection send envelopes or ACK deliveries. A newly authenticated connection may replace an older connection for the same identity only after the new authentication succeeds.

Message protocol limits are:

- message id: exactly 16 random non-zero bytes;
- UTF-8 text: at most 16 KiB before M3 encryption;
- M4 ciphertext: at most 64 KiB;
- encoded envelope: at most 96 KiB;
- encoded WSS frame: at most 100 KiB;
- message TTL: at most 72 hours.

The #51 durable mailbox additionally enforces:

- at most 500 retained messages / 16 MiB per recipient;
- at most 1,000 retained messages / 32 MiB per sender;
- at most 100,000 retained messages / 256 MiB globally;
- delivery pages of at most 50 envelopes;
- physical expiry cleanup batches of at most 1,000 rows.

Count/byte quotas are checked transactionally by the Go store and backed by a SQLite `BEFORE INSERT` trigger. The global physical quotas include expired rows awaiting deletion, so delayed cleanup cannot make disk use unbounded.

For an online recipient, #52 attempts direct opaque delivery without durable mailbox storage. The transport bounds active authenticated peers at 128, unauthenticated handshakes at 32, per-peer outbound queues at four frames, concurrent per-peer sends at four, global send workers at 128 and pending direct deliveries at 256. Authentication has a 10-second deadline and a direct attempt waits at most five seconds for authenticated ACK.

If direct delivery cannot complete under those bounds, the immutable canonical envelope may enter mailbox custody. `SendAccepted` intentionally does not reveal which path occurred, avoiding an explicit presence oracle. A failed same-identity authentication cannot affect the current authenticated peer; successful authentication replaces the old peer only after verification.

Delivery is at-least-once until ACK. Duplicate/reconnect delivery is expected and must be idempotent by authenticated message identity. Exact mailbox retry is idempotent only for the same sender/message id and identical retained routing/envelope bytes; conflicting reuse fails closed. ACK is authorized by the recipient's authenticated connection and may delete only that recipient's exact retained `(sender_identity_id, message_id)` row. Expiry is enforced at `now >= expires_at` even before physical cleanup.

The current #52 server slice supplies the routing layer required by M4. Remaining milestone work is #53 Android transport/history with crash-safe durable ACK handoff, followed by #54 end-to-end/security verification.

## Calling

Voice is audio-only for 1.0.

Planned media stack:

- WebRTC;
- Opus;
- ICE/STUN;
- P2P when possible;
- coturn relay when direct connectivity fails.

TURN is a packet relay, not a media server. It must not require plaintext voice content. M5 calling work is out of scope for M4.

## Security invariants

See the threat model for detail. Architecture changes must preserve:

1. server cannot decrypt message content;
2. server cannot decrypt voice content;
3. device private identity/session keys do not leave the device;
4. remote contact identity cannot silently change;
5. engine account/session replacement cannot silently bypass the pinned Kenato identity;
6. ratchet state cannot be exposed to callers before required durable state advancement;
7. M4 ACK cannot precede the required crash-safe local delivery handoff;
8. WSS routing identity requires cryptographic authentication, not an identity id alone;
9. authenticated inner M4 routing context must match the outer envelope;
10. retained mailbox bytes must match their indexed routing metadata and canonical envelope representation;
11. untrusted inputs, queues, timers and retained state are bounded;
12. no public user enumeration or intentional online-presence oracle;
13. no plaintext user content or secrets in logs.

## Deployment

The current non-production development host is an Oracle Cloud Infrastructure Ampere A1 ARM64 instance in Germany Central (Frankfurt), documented in `docs/development/OCI_HOST.md`.

The architecture remains provider-neutral: a small Linux VPS/free-tier instance and Raspberry Pi remain valid deployment targets, so backend resource usage should stay modest and dependencies minimal.

M0–M3 are complete and M4 is active under tracker #49. #50 and #51 are complete; #52 is the current authenticated WSS routing slice; #53–#54 remain. Public server exposure still waits for an explicitly reviewed deployment/TLS boundary. M5 has not started.

Self-hosted federation is explicitly out of scope for 1.0.
