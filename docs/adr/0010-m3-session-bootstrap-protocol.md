# ADR 0010 — M3 session-bootstrap protocol and server state

Status: Proposed for M3 implementation  
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

The server accepts the bundle only if the corresponding M2 identity publication exists and the binding signature verifies against that exact P-256 identity key. A device changing its Olm account must increment `account_generation`; a replacement generation starts at publication revision 1. Within one generation revisions are strictly monotonic except an exact same-revision replay, which is idempotent. Old generations and conflicting same-generation payloads are rejected.

The server never receives an Olm private key.

### Deterministic role

The M2 invite redeemer is the M3 initiator. The invite creator is the M3 responder. This role is fixed for the first session created from that invite and is not negotiated.

### One-time-key reservation

After M2 redemption, the redeemer may present the still-live invite token and a P-256 reservation proof. The server verifies that the invite is already redeemed by that exact redeemer and atomically reserves exactly one currently unreserved creator one-time key from the creator's current published account generation.

Reservation is bound to the invite token hash, creator identity id, redeemer identity id, creator account generation, and key id. Exact replay by the same redeemer returns the same reservation. A different redeemer, generation, or key for the same invite conflicts. If no creator key remains, the operation fails closed; M3 does not use Olm fallback keys.

Reserved keys are never offered to another invite, even if the initiating client disappears. They are retired when the invite is claimed or expires. Replenishment happens by publishing a later revision of the same account generation containing fresh one-time keys.

### Initial Olm frame

The redeemer creates the outbound Olm session locally and submits exactly one opaque Olm pre-key frame. The submit proof covers both identity ids, the invite token, creator account generation, creator reserved-key id, redeemer account generation, message type, and SHA-256 of the opaque frame.

The server verifies the redeemer's P-256 proof, verifies that the request matches the existing reservation, and retains the bounded opaque frame only as temporary invite-bootstrap state. It does not inspect or decrypt Olm content.

An exact replay of the same initial frame is idempotent. A different frame or metadata for the same invite conflicts.

### Creator claim

The creator claims the completed M3 bootstrap with the same P-256 creator proof model used for M2 claim. A successful M3 claim returns:

- the authenticated M2 redeemer identity bundle and redemption proof;
- the authenticated redeemer M3 session bundle;
- the creator one-time key that was reserved;
- the opaque Olm pre-key frame.

The server deletes the invite relationship and associated temporary reservation/init state in the same transaction. As with M2's destructive claim, loss of a successful claim response before the creator durably commits local state requires a fresh invite rather than retaining social/session bootstrap metadata for replay recovery.

### Resource bounds

- session bootstrap wire request/response: 128 KiB maximum;
- opaque Olm frame: 96 KiB maximum;
- Olm public keys: exactly 32 bytes;
- public one-time keys per bundle: 1..50;
- retained session bootstrap rows: no more than the M2 identity-row cap;
- all M3 HTTP handlers use the existing process-wide pre-crypto concurrency/rate gate and bounded operation deadline;
- SQLite writes remain serialized and subject to the existing busy timeout.

### M3/M4 boundary

`SessionCiphertext` defines an application/native cryptographic envelope only. M3 does not add WSS, routing, offline mailbox, acknowledgements, retries, conversation history, or any server endpoint for ordinary encrypted messages. Those remain M4.

## Persistence and failure semantics

Session bootstrap publications and temporary invite-bootstrap state are stored in SQLite/WAL. Database state is fail-closed on unknown schema versions. Publication replacement, OTK reservation, init submission, and claim/deletion are transactional.

The server does not attempt to recreate missing or corrupt session bootstrap material. Clients must treat missing, mismatched, changed, or unverifiable M3 identity/account material as a failed bootstrap rather than silently starting a different session identity.

## Compatibility

The M3 schema extends the existing `kenato.v1` package in a separate file and does not reuse or change M2 field numbers. Unsupported `protocol_version` values fail explicitly. Kenato-owned signatures use domain-separated canonical byte framing independent of protobuf serialization. Deterministic vectors are documented in `docs/security/M3_TEST_VECTORS.md`.

## Security impact

This design exposes to the server only public Olm account material, a bounded one-time-key allocation decision, temporary invite relationship metadata already present in M2, and an opaque authenticated ciphertext frame. It does not expose any Kenato or Olm private key or plaintext.

A malicious server can deny service or withhold/replay stale valid public session material within accepted version/generation rules. It cannot substitute a different M3 engine identity or alter the initial frame without causing a P-256 binding/proof verification failure at a correct client, assuming the pinned Kenato identity key remains uncompromised.
