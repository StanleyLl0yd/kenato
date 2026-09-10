# Kenato Protocol

The Kenato wire protocol is platform-independent and versioned independently of Android and server releases.

## Current state

M0 established the outer server-routable envelope. M1 established device-local identity. M2 completed public identity publication and invite/contact establishment. M3 is in progress and adds authenticated asynchronous E2EE session bootstrap under the existing `kenato.v1` package.

The current schemas live under:

`protocol/kenato/v1/`

- `envelope.proto` — minimum server-routable encrypted envelope for later messaging;
- `contact.proto` — M2 public identity publication and invite/contact establishment;
- `session.proto` — M3 public session-account material, one-time-key reservation, initial Olm pre-key frame exchange, and the local/native ciphertext envelope.

M3 deliberately does **not** add WebSocket routing, an offline mailbox, acknowledgements, conversation history, or product messaging. Those remain M4.

## M2 invite URI

QR codes and deep links carry exactly this URI form:

```text
kenato://invite/v1/<creator-identity-id>/<invite-token>/<invite-signature>
```

All three path components are unpadded Base64url. The decoded creator identity id is exactly 32 bytes, the decoded invite token is exactly 32 bytes, and the invite signature is a bounded DER ECDSA signature made by the creator identity key over the canonical invite payload below.

No display name, phone number, email address, server address, or other user-searchable identifier is embedded in the invite.

## Canonical signature payloads

All integer fields below are unsigned big-endian. Length fields used by M2 are 32-bit. Timestamps are represented as non-negative 64-bit Unix seconds after validation. Identity ids and invite tokens are exactly 32 raw bytes.

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

Within one account generation, the Olm identity public keys do not change. Publication revisions increase monotonically; an exact same-revision replay is idempotent and conflicting reuse is rejected. An account replacement increments `account_generation` by exactly one and restarts `publication_revision` at 1. A creator account replacement invalidates reservations that consume an OTK from the replaced generation; a redeemer account replacement does not discard another identity's already reserved creator OTK.

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

## Server-visible state

Through M3 the server may retain only the minimum state required by the implemented identity, invite, and asynchronous session-bootstrap contracts:

- public Kenato identity/prekey material and monotonic M2 publication revision;
- SHA-256 invite-token hashes and temporary invite relationship state from M2;
- authenticated public Olm session-account identity/one-time-key material;
- current session-account generation/publication revision and bounded key-allocation state;
- while a redeemed invite is awaiting creator claim, the reserved creator public one-time key and a bounded opaque Olm pre-key frame plus authenticated proof metadata.

The server never receives a Kenato private identity key, an Olm private/session key, the session-init control record in plaintext, or plaintext user content. There is no public identity or session-key lookup/search endpoint; M3 bootstrap disclosure is reachable only through the authenticated live invite relationship.

## Resource limits

Current M3 protocol bounds include:

- outer M3 session-bootstrap request/response: at most 128 KiB;
- encoded public session bundle: at most 64 KiB;
- opaque Olm initialization frame: at most 96 KiB;
- Olm public keys: exactly 32 bytes;
- published M3 one-time public keys: 1..50 per bundle;
- account generations, publication revisions, and one-time-key ids must fit the positive signed 64-bit SQLite domain.

Implementations additionally bound concurrency, operation deadlines, retained rows, local session state, and skipped-message-key behavior.

## Rules

- Unknown protocol versions must fail safely.
- Old wire data must never be silently reinterpreted with new semantics.
- Protocol changes must consider compatibility, malformed input, replay, duplication, reordering, and persistence/restart behavior.
- Deterministic test vectors are required when Kenato-owned canonical cryptographic framing is introduced.
- Private identity/prekey/session keys and plaintext user content never belong in server-visible protocol messages.
- Identity/session public keys, signatures, repeated counts, request bodies, invite attempts, retained state, and expensive work are explicitly bounded by implementations.
- Contact identity is pinned locally after verification and must not change silently.
- M3 session engine keys are subordinate to and authenticated by the pinned Kenato P-256 identity; they are never an independent trust root.
- M3 stops before WebSocket routing, offline mailbox storage, acknowledgements/retries, local conversation history, or calling behavior.

Deterministic M2 framing vectors live in `docs/security/M2_TEST_VECTORS.md`. M3 framing vectors live in `docs/security/M3_TEST_VECTORS.md`.
