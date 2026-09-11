# ADR 0010 — M3 session-bootstrap protocol and server state

Status: Accepted  
Date: 2026-09-10

## Context

ADR 0009 selects vodozemac 0.10.0 Olm as the reviewed M3 asynchronous session engine while retaining the existing Kenato ECDSA P-256 identity as the sole contact trust anchor. M2 already provides invite-only creator/redeemer establishment, authenticated public P-256 identity bundles, a 24-hour single-use invite token, and local peer identity pinning.

M3 needs a narrow server-assisted bootstrap so the invite redeemer can establish an Olm session asynchronously without public user lookup, without handing private key material to the server, and without introducing M4 WebSocket routing or offline messaging.

## Decision

M3 adds `kenato.v1/session.proto` and a server-side session-bootstrap boundary with the following rules.

### Public account publication

Each device publishes a bounded `SessionBootstrapBundle` containing:

- its existing Kenato identity id;
- a positive account generation;
- a positive publication revision within that generation;
- the Olm Ed25519 identity public key;
- the Olm Curve25519 identity public key;
- between 1 and 50 public Olm Curve25519 one-time keys;
- a P-256 binding signature from the existing Kenato identity over all of the above.

The server accepts the bundle only if the corresponding M2 identity publication exists and the binding signature verifies against that exact P-256 identity key. A device changing its Olm account must increment `account_generation` by exactly one and a replacement generation starts at publication revision 1. Within one generation, revisions are strictly monotonic except an exact same-revision replay, which is idempotent. The two Olm account identity public keys cannot change within one generation. Old/skipped generations, conflicting same-generation payloads, or a non-1 first revision for a replacement generation are rejected.

The first locally created account may use any positive representable generation because M3 has no shipped predecessor state; subsequent replacement is strictly `previous + 1`. The Android/native implementation is expected to begin new installations at generation 1.

The server never receives an Olm private key.

### Deterministic role

The M2 invite redeemer is the M3 initiator. The invite creator is the M3 responder. This role is fixed for the first session created from that invite and is not negotiated.

### One-time-key reservation

After M2 redemption, the redeemer may present the still-live invite token and a P-256 reservation proof. The server verifies that the invite is already redeemed by that exact redeemer and atomically reserves exactly one currently unreserved creator one-time key from the creator's current published account generation.

Reservation is bound to the invite token hash, creator identity id, redeemer identity id, creator account generation, and key id. Exact replay by the same redeemer returns the same signed creator snapshot and reservation while that creator account generation remains current. A creator account-generation replacement invalidates outstanding reservations owned by the old creator generation; a later reserve against the still-live invite must allocate from the new creator generation. A redeemer account-generation replacement does not discard an already allocated creator OTK; if that redeemer had already submitted an initial frame, the old-generation init is invalidated while the creator reservation remains available for a replacement init from the new redeemer generation. A different redeemer or conflicting reservation for the same invite fails closed. If no creator key remains, the operation fails closed; M3 does not use Olm fallback keys.

Within a generation, one-time-key ids are positive, strictly increasing in each signed publication and tracked with a monotonic server high-water mark. A currently available/reserved key may remain present in a later signed publication only with the same id and exact bytes. If a reservation disappears because its invite expires before the creator learns which OTK was consumed, that same id/key may remain in the immediately following signed snapshot so replenishment is not blocked, but the server treats it as historical and never returns it to the available pool. An id that the previous signed publication had already omitted remains explicitly retired and cannot be resurrected. Fresh replenishment uses new ids above the prior high-water mark.

The server also rejects aliasing a currently available/reserved public OTK under a different bookkeeping id. It deliberately does not retain an unbounded historical set of every prior OTK public-key byte string. Correct clients must generate genuinely fresh vodozemac OTK material when publishing a fresh bookkeeping id; reusing old private/public OTK material under a new id violates the client contract.

### Initial Olm frame

The redeemer creates the outbound Olm session locally and submits exactly one opaque Olm pre-key frame. The submit proof covers both identity ids, the invite token, creator account generation, creator reserved-key id, redeemer account generation, message type, and SHA-256 of the opaque frame.

The encrypted plaintext inside that initial Olm frame is a Kenato protocol-control record, not user content. Its canonical bytes bind both Kenato identity ids, SHA-256 of the invite token, the creator account generation and reserved OTK id, and the redeemer account generation. This inner authenticated binding is checked by the creator after Olm decryption and before the inbound session is accepted, so the opaque pre-key frame cannot be transplanted into a different invite/contact/account context even independently of the outer submit proof. The deterministic framing is specified in `protocol/README.md` and `docs/security/M3_TEST_VECTORS.md`; the server never parses this plaintext.

The server verifies the redeemer's P-256 proof, verifies that the request matches the existing reservation, snapshots the redeemer's currently authenticated session bundle, and retains the bounded opaque frame only as temporary invite-bootstrap state. It does not inspect or decrypt Olm content.

An exact replay of the same canonical submit payload is idempotent. A different frame or metadata for the same invite conflicts. Only Olm pre-key message type is accepted for this bootstrap operation.

### Creator claim

The creator claims the completed M3 bootstrap with a P-256 creator proof. A successful M3 claim returns:

- the authenticated M2 redeemer identity bundle and redemption proof;
- the authenticated redeemer M3 session bundle captured for the submitted initialization;
- the exact creator account generation and reserved one-time-key id/public key;
- the opaque Olm pre-key frame;
- the redeemer's original submit signature.

The server stores the signed creator M3 snapshot from which the OTK was allocated and re-validates it internally at claim time; the snapshot itself is not redundantly returned on the wire because the creator already owns the corresponding local account state. The service re-validates the stored M2/M3 bundles, verifies that the reserved OTK belongs to that signed creator snapshot, reconstructs the submit canonical payload and re-verifies the redeemer signature before returning the result. The Android/native responder must additionally require the returned creator generation and exact OTK id/public bytes to match its local account material, decrypt the initial Olm frame, and verify the inner session-init control record before durably accepting the inbound session.

The server deletes the invite relationship and associated temporary reservation/init state in the same SQLite transaction. As with M2's destructive claim, loss of a successful claim response before the creator durably commits local state requires a fresh invite rather than retaining social/session-bootstrap metadata for replay recovery.

### Resource bounds

- session-bootstrap wire request/response: 128 KiB maximum;
- opaque Olm frame: 96 KiB maximum;
- Olm public keys: exactly 32 bytes;
- public one-time keys per bundle: 1..50;
- retained current session-bootstrap rows: no more than the M2 identity-row cap;
- one reservation/init chain per bounded live invite;
- all M3 HTTP handlers share the existing process-wide pre-crypto concurrency/rate gate and bounded operation deadline with M2;
- SQLite writes remain serialized and subject to the existing busy timeout.

### M3/M4 boundary

`SessionCiphertext` defines an application/native cryptographic envelope only. M3 does not add WSS, routing, offline mailbox, acknowledgements, retries, conversation history, or any server endpoint for ordinary encrypted messages. Those remain M4.

## Persistence and failure semantics

M3 upgrades the additive SQLite schema from M2 `user_version = 1` to `user_version = 2`. Existing M2 identities/invites remain in their original tables; M3 adds current public session-account bundles, available OTKs, temporary invite reservations, and temporary init frames/proofs. Unknown newer schema versions fail closed.

Session bootstrap publication replacement, OTK reservation, init submission, and claim/deletion are transactional. Reservation deletes the chosen OTK from the available pool in the same transaction that creates the reservation. Successful claim deletes the invite; foreign-key cascades delete the reservation/init records in that transaction. Expired invites cannot reserve, submit, or claim; startup/hourly retention cleanup deletes expired invite rows and cascades temporary M3 rows.

The server does not attempt to recreate missing or corrupt session-bootstrap material. Clients must treat missing, mismatched, changed, or unverifiable M3 identity/account material as a failed bootstrap rather than silently starting a different session identity.

## Compatibility

The M3 schema extends the existing `kenato.v1` package in a separate file and does not reuse or change M2 field numbers. Unsupported `protocol_version` values fail explicitly. Kenato-owned signatures and the initial-session control plaintext use domain-separated canonical byte framing independent of protobuf serialization. Deterministic bootstrap/reservation/submit/claim/control vectors are documented in `docs/security/M3_TEST_VECTORS.md` and exercised by Go tests.

## Security impact

This design exposes to the server only public Olm account material, a bounded one-time-key allocation decision, temporary invite relationship metadata already present in M2, and an opaque authenticated ciphertext frame. It does not expose any Kenato or Olm private key or plaintext.

A malicious server can deny service, withhold public keys/frames, exhaust allocations, or replay stale valid public session material within accepted version/generation rules. It cannot substitute a different M3 engine identity or alter/transplant the initial frame without causing P-256 binding/proof, inner control-record, or local pin verification failure at a correct client, assuming the pinned Kenato identity key and Olm primitives remain uncompromised.

This ADR covers only the protocol/server bootstrap portion of M3. Native Olm account/session creation, encrypted snapshot persistence, rollback-resistant commit ordering, peer session pins, replay/reordering behavior, and JNI/NDK supply-chain controls remain governed by ADR 0009 and must be implemented and reviewed before M3 is complete.
