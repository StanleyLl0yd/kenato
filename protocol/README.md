# Kenato Protocol

The Kenato wire protocol is platform-independent and versioned independently of Android and server releases.

## Current state

M0 established the outer server-routable envelope. M1 established device-local identity. M2 completed public identity publication and invite/contact establishment. M3 completed authenticated asynchronous E2EE session bootstrap under the existing `kenato.v1` package. M4 Minimal Messaging is complete across protocol/auth (#50), bounded mailbox persistence (#51), authenticated WSS/direct routing (#52), Android messaging/history (#53), and final repository-wide end-to-end/security verification (#54). Final audit PR #60 and its resulting exact `main` revision passed the required verification matrix. #59/M4.5 is the next permitted milestone; M5 remains blocked until #59 completes.

The current schemas live under `protocol/kenato/v1/`:

- `envelope.proto` — server-routable opaque encrypted envelope;
- `contact.proto` — M2 public identity publication and invite/contact establishment;
- `session.proto` — M3 public session-account material, one-time-key reservation, initial Olm pre-key frame exchange, and the local/native ciphertext boundary;
- `messaging.proto` — M4 authenticated WSS control frames, delivery ACKs, generic send acceptance/errors, and the plaintext structure that is encrypted by the established M3 session.

M4 does not change the E2EE trust root. The existing long-lived Kenato P-256 identity authenticates connection ownership, while ordinary user text remains inside M3 authenticated ciphertext. The server may see only bounded routing metadata and opaque ciphertext.

## M2 invite URI

QR codes and deep links carry exactly this URI form:

```text
kenato://invite/v1/<creator-identity-id>/<invite-token>/<invite-signature>
```

All three path components are unpadded Base64url. The decoded creator identity id is exactly 32 bytes, the decoded invite token is exactly 32 bytes, and the invite signature is a bounded DER ECDSA signature made by the creator identity key over the canonical invite payload below.

No display name, phone number, email address, server address, or other user-searchable identifier is embedded in the invite.

## Canonical signature payloads

All integer fields below are unsigned big-endian unless explicitly described otherwise. Length fields used by M2 are 32-bit. Timestamps are validated non-negative signed 64-bit Unix seconds when represented in protobuf/SQLite. Identity ids and invite tokens are exactly 32 raw bytes.

### M2 identity publication

The publication signature uses SHA-256 with ECDSA P-256 over this exact byte sequence:

1. UTF-8/ASCII `KENATO-PUBLICATION-V1` followed by one NUL byte;
2. 32-byte identity id;
3. 64-bit publication revision;
4. identity public-key length, then exact X.509 SubjectPublicKeyInfo bytes;
5. signed-prekey id;
6. signed-prekey creation timestamp;
7. signed-prekey public-key length and bytes;
8. signed-prekey signature length and bytes;
9. one-time-prekey count;
10. each one-time prekey in strictly increasing id order: id, creation timestamp, public-key length, public-key bytes.

The publication signature itself is excluded from the signed payload. A publication revision is positive and must increase when the published bundle changes; an implementation may accept an exact replay of the same revision idempotently but must reject a different payload at an already accepted revision.

### M2 invite creation/binding

The invite signature payload is:

```text
KENATO-INVITE-V1\0 || creator_identity_id[32] || invite_token[32]
```

This lets the redeemer verify end-to-end that the token was created by the identity named in the URI, rather than trusting the server to bind a token to an identity correctly.

### M2 redemption proof

The redeemer signs:

```text
KENATO-REDEEM-V1\0 || creator_identity_id[32] || redeemer_identity_id[32] || invite_token[32]
```

The server retains this bounded signature only until the creator claims the completed invite or the invite record expires. The creator verifies it before pinning the redeemer identity.

An exact redemption retry by the same redeemer identity is idempotent and returns the original redemption timestamp. A different redeemer cannot replace the first successful redemption.

### M2 claim authentication

The creator signs:

```text
KENATO-CLAIM-V1\0 || creator_identity_id[32] || invite_token[32]
```

Possession of the token alone is therefore not sufficient to retrieve the redeemer bundle from the server.

Successful claim is intentionally destructive: the server deletes the invite relationship row after retrieving the bounded result. A repeated claim therefore returns not-found. If the successful response is lost before the creator commits its local contact state, recovery uses a fresh invite rather than a retained server-side replay cache.

## M3 session bootstrap

The M2 invite redeemer is the deterministic initiator of the first M3 Olm session. The invite creator is the responder. M3 uses vodozemac Olm/Double Ratchet, while the existing M1/M2 ECDSA P-256 identity remains the Kenato trust anchor.

An M3 `SessionBootstrapBundle` contains only public material: the Kenato identity id, an account generation, a publication revision, 32-byte Olm Ed25519 and Curve25519 identity public keys, 1..50 32-byte Curve25519 one-time public keys, and a P-256 binding signature.

Within one account generation, the Olm identity public keys do not change. Publication revisions increase monotonically; an exact same-revision replay is idempotent and conflicting reuse is rejected. An account replacement increments `account_generation` by exactly one and restarts `publication_revision` at 1. A creator account replacement invalidates reservations that consume an OTK from the replaced generation; a redeemer account replacement preserves another identity's already reserved creator OTK but invalidates any previously submitted init from the replaced redeemer generation so a replacement frame can be submitted against that same reservation.

### M3 session-account binding

The Kenato P-256 identity signs SHA-256 of this exact byte sequence:

```text
KENATO-SESSION-BOOTSTRAP-V1\0
|| identity_id[32]
|| account_generation:u64
|| publication_revision:u64
|| olm_ed25519_identity_key[32]
|| olm_curve25519_identity_key[32]
|| one_time_prekey_count:u32
|| repeated(one_time_prekey_id:u64 || one_time_prekey_public_key[32])
```

One-time-prekey ids are positive and strictly increasing. Public-key bytes must be unique inside the publication and must not alias either Olm account identity public key. The binding signature itself is excluded from the signed payload.

A monotonic high-water mark prevents old OTK bookkeeping ids from becoming available again. A currently available or reserved id may remain in a later signed publication only with identical public-key bytes. If an invite expires after reserving an OTK before the creator learns which OTK was consumed, the same id/key may remain in the immediately following signed publication without blocking fresh replenishment, but the server treats that stale entry as historical and does not reinsert it into the available pool. An id already omitted by the previous signed publication remains retired. Fresh OTKs use ids above the high-water mark, and a currently known OTK public key cannot be aliased under another id.

### M3 one-time-key reservation

After the M2 invite has been redeemed, the redeemer signs:

```text
KENATO-SESSION-RESERVE-V1\0
|| creator_identity_id[32]
|| redeemer_identity_id[32]
|| invite_token[32]
```

The server verifies the redeemer's pinned P-256 identity and atomically reserves exactly one available creator M3 one-time key. An exact retry for the same invite/redeemer returns the same reservation while that creator account generation remains current. A creator account-generation replacement retires old-generation reservations and requires allocation from the replacement generation. A reserved key is never returned to another invite. Kenato M3 deliberately does not use Olm fallback keys; exhaustion fails closed until the creator publishes fresh one-time keys.

### M3 initial-session control plaintext

Before creating the first Olm pre-key frame, the redeemer constructs this exact protocol-control plaintext:

```text
KENATO-SESSION-INIT-CONTROL-V1\0
|| creator_identity_id[32]
|| redeemer_identity_id[32]
|| sha256(invite_token)[32]
|| creator_account_generation:u64
|| creator_one_time_prekey_id:u64
|| redeemer_account_generation:u64
```

This is protocol control data, not user content. It is encrypted and authenticated by the first Olm pre-key message. The server never receives it in plaintext and never parses it. After accepting/decrypting the pre-key frame, the creator must compare the complete control record against the expected invite/contact identities, invite-token hash, local creator account generation/OTK, and authenticated redeemer account generation before committing the inbound session. A mismatch fails closed.

### M3 initial-session submission

The redeemer submits the resulting opaque Olm pre-key frame. The P-256 submit proof signs SHA-256 of:

```text
KENATO-SESSION-INIT-SUBMIT-V1\0
|| creator_identity_id[32]
|| redeemer_identity_id[32]
|| invite_token[32]
|| creator_account_generation:u64
|| creator_one_time_prekey_id:u64
|| redeemer_account_generation:u64
|| olm_message_type:u32
|| sha256(olm_message)[32]
```

For this operation `olm_message_type` must be the Olm pre-key type. The server does not parse or decrypt `olm_message`. Exact retries are idempotent by the authenticated canonical payload; conflicting replacement of the initialization frame is rejected. The outer P-256 proof and inner Olm-encrypted control record intentionally bind the same bootstrap context at different trust boundaries.

### M3 creator claim

The creator authenticates the terminal session-bootstrap claim with:

```text
KENATO-SESSION-CLAIM-V1\0 || creator_identity_id[32] || invite_token[32]
```

The response contains the authenticated M2 redeemer identity/proof, the redeemer's authenticated M3 public session bundle, the exact creator account generation and reserved one-time public key, the opaque Olm pre-key frame, and the redeemer's submit signature. The server also retains and re-validates internally the signed creator session snapshot from which the reservation was allocated; that snapshot is not redundantly returned because the creator owns the corresponding local account state. The creator must verify the returned generation/key against that local account before creating the inbound Olm session and then verify the decrypted control plaintext before committing it.

A successful M3 claim deletes the invite and temporary reservation/init state in the same transaction. A claim replay returns not-found. Expired invites remain unusable at the exact expiry boundary and normal retention cleanup deletes their cascaded M3 temporary state.

## M4 minimal messaging

M4 uses one authenticated WSS connection per local Kenato identity. The server must not infer authentication from an identity id supplied in a URL, query parameter, envelope, or first client frame. Instead each new connection begins unauthenticated with a random challenge.

### M4 WSS identity authentication

The server sends exactly 32 random challenge bytes plus a short expiry. Challenge state is scoped to that connection, single-use, and valid for at most 30 seconds. The client proves possession of its existing Kenato P-256 identity key by signing SHA-256 of this exact canonical payload:

```text
KENATO-MESSAGING-AUTH-V1\0
|| identity_id[32]
|| challenge[32]
|| expires_at_unix_seconds:u64
```

The client returns `MessagingAuthResponse` carrying the same identity id, challenge and expiry plus the bounded DER ECDSA signature. The server resolves the already-published Kenato identity key for that exact identity id, validates the challenge/expiry and signature, consumes the challenge, and only then associates the socket with that identity.

A malformed, stale, reused, wrong-identity, unknown-identity, or invalidly signed authentication attempt fails closed. Public failure behavior must not distinguish whether an identity exists. A newly authenticated connection may replace the previously authenticated connection for the same identity; connection replacement must occur only after the new authentication succeeds.

### M4 encrypted message structure

An application message uses a fresh cryptographically random 16-byte non-zero `message_id`. Before calling the M3 session encrypt primitive, the sender serializes `MessagingPlaintext`, which contains:

- protocol version;
- sender identity id;
- recipient identity id;
- 16-byte message id;
- sender timestamp;
- expiry timestamp;
- UTF-8 text, at most 16 KiB.

That serialized record is the M3 application plaintext. The resulting opaque authenticated Olm ciphertext is placed into `Envelope.ciphertext`. The routing envelope carries only fields the relay requires: protocol version, sender identity id, recipient identity id, message id, expiry, and ciphertext.

The receiver must decrypt first and then compare **all** duplicated routing context from the authenticated inner plaintext against the outer envelope: sender identity id, recipient identity id, message id, and expiry. Any mismatch fails closed and must not be acknowledged. This prevents a relay that cannot forge M3 ciphertext from silently relabeling an envelope, changing deduplication identity, transplanting it to another recipient, or extending its lifetime.

The sender timestamp is intentionally inner-only. It is conversation data and is not required for routing.

### M4 send acceptance and privacy

A client may submit an `Envelope` only after its WSS connection is authenticated. The outer `sender_identity_id` must equal the authenticated connection identity before any delivery/storage work is attempted.

`MessagingSendAccepted` deliberately does not reveal whether the recipient was online or whether the server used direct or durable custody. Acceptance means that the server either received an authenticated recipient ACK for the direct-delivery attempt or accepted the exact bounded envelope into durable mailbox custody. Generic public errors must not become recipient-existence or presence oracles.

The server never parses `MessagingPlaintext` and never needs the semantic user text or M3 session keys.

### M4 delivery, retry and acknowledgement

Delivery is at-least-once until the authenticated recipient acknowledges the exact `(sender_identity_id, message_id)` pair. Duplicate delivery is therefore expected. The client deduplicates by the authenticated inner routing context, not by unauthenticated UI text or arrival order.

ACK is valid only on the authenticated recipient connection and deletes only that recipient's matching retained row. An ACK from another identity, for a different sender/message pair, or for a missing/expired retained row must not delete unrelated state.

Direct online delivery should avoid durable storage when possible. If direct delivery is unavailable or fails to receive a valid ACK within the bounded direct-attempt policy, the server may move the same immutable envelope into bounded durable mailbox custody. It must not rewrite `message_id`, expiry, sender, recipient, or ciphertext while moving between custody modes.

Reconnect/retry may therefore redeliver an envelope. Ordering is best-effort transport order only; correctness must not depend on global sequencing beyond M3's authenticated ratchet behavior and M4's explicit message identity.

### M4 crash-safe client acknowledgement boundary

M3 already durably commits advanced ratchet state before returning inbound plaintext. M4 adds another durability requirement: the Android client must not ACK merely because decrypt succeeded. If the process crashed after the ratchet commit but before conversation state recorded the plaintext/message id, a redelivered ciphertext may correctly be rejected by the ratchet as a replay and the user message could be lost.

The completed #53 implementation provides a crash-safe durable delivery handoff/journal tied to the completed M3 decrypt result. The exact authenticated message identity and plaintext are durably recoverable before ACK. Conversation-history insertion is idempotent, and only a completed durable handoff/history commit permits the network ACK.

### M4 expiry and bounds

The first M4 contract fixes these hard maximums:

- message id: exactly 16 bytes and not all zero;
- UTF-8 text: at most 16 KiB;
- M3 ciphertext carried by M4: at most 64 KiB;
- encoded envelope: at most 96 KiB;
- encoded WSS frame: at most 100 KiB;
- message lifetime: positive and at most 72 hours from accepted send time;
- authentication challenge: exactly 32 bytes, at most 30 seconds lifetime;
- durable mailbox design bound: at most 500 retained messages per recipient.

Exact mailbox byte/global quotas and direct-delivery timers are implemented and regression-tested by the completed M4 server slices; they may be stricter than the protocol maxima but may not silently exceed them.

## Server-visible state

Through M3 the server may retain the minimum state required by the implemented identity, invite, and asynchronous session-bootstrap contracts:

- public Kenato identity/prekey material and monotonic M2 publication revision;
- SHA-256 invite-token hashes and temporary invite relationship state from M2;
- authenticated public Olm session-account identity/one-time-key material;
- current session-account generation/publication revision and bounded key-allocation state;
- while a redeemed invite is awaiting creator claim, the reserved creator public one-time key and a bounded opaque Olm pre-key frame plus authenticated proof metadata.

M4 additionally defines server-visible routing metadata for ordinary messages: sender identity id, recipient identity id, random message id, expiry, ciphertext length/content, connection timing, and bounded mailbox/delivery state. The server still never receives ordinary message plaintext or any private identity/session key. `MessagingPlaintext` exists only at the endpoints inside M3 authenticated encryption.

There remains no public user-search endpoint. M4 routing authorization is based on an authenticated existing identity rather than making identity ids public credentials.

## Resource limits

Current protocol bounds include:

- outer M3 session-bootstrap request/response: at most 128 KiB;
- encoded public M3 session bundle: at most 64 KiB;
- opaque M3 initialization frame: at most 96 KiB;
- Olm public keys: exactly 32 bytes;
- published M3 one-time public keys: 1..50 per bundle;
- account generations, publication revisions, and one-time-key ids must fit the positive signed 64-bit SQLite domain;
- M4 message id: exactly 16 bytes;
- M4 application text: at most 16 KiB UTF-8;
- M4 ciphertext: at most 64 KiB;
- M4 envelope: at most 96 KiB;
- M4 WSS frame: at most 100 KiB;
- M4 message TTL: at most 72 hours;
- M4 auth challenge lifetime: at most 30 seconds;
- M4 durable mailbox design bound: 500 retained messages per recipient.

Implementations additionally bound concurrency, operation deadlines, retained rows/bytes, local session/history state, retry timers, connection queues, and skipped-message-key behavior.

## Rules

- Unknown protocol versions must fail safely.
- Old wire data must never be silently reinterpreted with new semantics.
- Protocol changes must consider compatibility, malformed input, replay, duplication, reordering, expiry and persistence/restart behavior.
- Deterministic test vectors are required when Kenato-owned canonical cryptographic framing is introduced.
- Private identity/prekey/session keys and plaintext user content never belong in server-visible protocol messages.
- Identity/session public keys, signatures, repeated counts, request bodies, WSS frames, envelopes, queues, retained state, retry timers and expensive work are explicitly bounded by implementations.
- Contact identity is pinned locally after verification and must not change silently.
- M3 session engine keys are subordinate to and authenticated by the pinned Kenato P-256 identity; they are never an independent trust root.
- M4 WSS authentication proves possession of that same P-256 identity; an identity id by itself is never a credential.
- Outer M4 routing context must match the authenticated inner plaintext after M3 decrypt before local delivery or ACK.
- ACK is sent only after the client has a crash-safe durable delivery handoff/history commit.
- M4 stops before calling/WebRTC behavior; M5 must not be pulled into messaging transport work.

Deterministic M2 framing vectors live in `docs/security/M2_TEST_VECTORS.md`. M3 framing vectors live in `docs/security/M3_TEST_VECTORS.md`. M4 authentication framing vectors live in `docs/security/M4_TEST_VECTORS.md`.
