# Kenato Server

Kenato's backend is a deliberately small Go service. M2 provides authenticated identity publication and invite/contact establishment. M3 adds authenticated asynchronous session bootstrap. M4 is active: #50 defines the messaging/auth contract, #51 provides bounded durable mailbox custody, and the current #52 slice adds authenticated WSS routing with direct delivery plus bounded mailbox fallback.

## Current surface

- bounded HTTP server configuration and graceful shutdown;
- `GET /healthz`;
- `POST /v1/identity/publish`;
- `POST /v1/invites`;
- `POST /v1/invites/redeem`;
- `POST /v1/invites/claim`;
- `POST /v1/session/bootstrap/publish`;
- `POST /v1/session/bootstrap/reserve`;
- `POST /v1/session/init`;
- `POST /v1/session/init/claim`;
- authenticated `GET /v1/messaging/ws` WebSocket upgrade for M4 routing;
- no public identity, session-bootstrap, mailbox, or presence lookup/search endpoint;
- bounded Protocol Buffers request/response and WebSocket framing;
- strict P-256 identity/prekey/signature verification for M2 plus P-256 authentication of M3 Olm public account material, bootstrap proofs, and M4 WSS connection ownership;
- SQLite/WAL persistence for public identity bundles, public M3 Olm account material/available OTKs, and temporary invite/session-bootstrap lifecycle state;
- a separate SQLite/WAL M4 mailbox database that retains only bounded opaque encrypted envelopes plus minimum routing/timing metadata;
- single-use 32-byte invite tokens with 24-hour expiry, stored only as SHA-256 hashes at rest;
- monotonic M2 publication revisions and M3 account-generation/publication-revision transitions with exact-replay idempotency;
- atomic single-use creator OTK reservation bound to the already-redeemed invite; fallback keys are not supported;
- bounded identity/invite/session-bootstrap counts and a coarse process-wide pre-crypto concurrency/rate gate shared by M2 and M3;
- bounded M4 handshake, authenticated-connection, outbound-queue, pending-direct and send-worker state;
- expired invite and mailbox cleanup at startup/hourly retention boundaries;
- generic public handling for missing/offline identities so the API does not expose a dedicated identity-existence or online-presence response.

The server binds to `127.0.0.1:8080` by default. `KENATO_LISTEN_ADDR` may override the listener only for a reviewed deployment boundary. Public deployment is expected to terminate TLS in front of the loopback service. The Go handler therefore sees ordinary proxied HTTP/WebSocket traffic and never treats forwarded address headers as identity credentials.

`KENATO_DB_PATH` selects the M2/M3 SQLite database; the default is `kenato.db`. `KENATO_MAILBOX_DB_PATH` selects the M4 mailbox database; the default is `kenato-mailbox.db`. Deployment should place both in a dedicated service-owned state directory. Both database paths must be regular files restricted to mode `0600`; both use WAL mode and synchronous durability `FULL`. The M2/M3 database additionally keeps foreign keys enabled.

The contact/session SQLite schema is versioned with `PRAGMA user_version`; M3 session bootstrap is schema v2. The independent mailbox database starts with its own schema v1 and rejects unknown newer versions. Keeping the mailbox lifecycle separate prevents M4 expiry/ACK cleanup from becoming coupled to destructive invite/session-bootstrap lifecycle operations.

The built-in M2/M3 rate gate is intentionally process-wide: at most four concurrent gated operations and at most 600 accepted gated operations per one-minute process window. Source-aware/distributed edge limits should be implemented only together with the reviewed reverse-proxy/TLS deployment boundary rather than by trusting arbitrary forwarded-address headers in the loopback service. M4 WSS has its own explicit connection, queue and send-operation bounds described below.

## M3 bootstrap semantics

The invite redeemer is the deterministic M3 initiator and the invite creator is the responder. Each client publishes only public Olm account material: exact 32-byte Ed25519/Curve25519 identity public keys plus 1..50 public Curve25519 OTKs. The entire bundle is authenticated by the existing Kenato P-256 identity.

After normal M2 redemption, the exact redeemer can authenticate a reservation request for that still-live invite. SQLite atomically removes one creator OTK from the available pool and records the allocation against the invite token hash. Exact reservation retry receives the same key; another invite cannot receive that key. Exhaustion returns a conflict/unavailable result instead of falling back to reusable key material.

The redeemer then submits one bounded opaque Olm pre-key frame. Its P-256 submit proof binds both identity ids, the invite token, creator account generation and OTK id, redeemer account generation, Olm message type, and SHA-256 of the opaque frame. Exact submit replay is idempotent; conflicting metadata/frame bytes fail closed.

Creator-side M3 claim requires the creator P-256 proof and returns the M2 peer proof, authenticated redeemer M3 bundle, exact creator account generation/OTK allocation, opaque pre-key frame, and original redeemer submit signature. This gives the client enough information to independently re-verify the server-retained bootstrap data. The server then deletes the invite, and foreign-key cascades delete the temporary reservation/init rows in the same transaction.

## M4 mailbox semantics

The #51 mailbox core is not a public endpoint. It is consumed only through the authenticated #52 WSS routing service.

Before mailbox custody is accepted, the service requires the authenticated sender to match the envelope sender, revalidates the #50 envelope bounds at the server acceptance time, and confirms recipient existence through the internal contact identity directory. Unknown recipients are represented by the same generic mailbox-rejection class used for other rejected sends.

A retained row is unique by `(sender_identity_id, message_id)`. An exact retry with unchanged recipient, expiry, ciphertext length and retained encoded envelope is idempotent. Reuse of the same sender/message id with different data is rejected instead of overwriting or retargeting the retained message.

ACK deletion matches authenticated recipient, stored sender and message id. A mismatch deletes nothing; an exact duplicate ACK after successful deletion is harmless. Expired rows are excluded from delivery exactly at `now >= expires_at`, independently of whether physical cleanup has already run.

## M4 WSS routing semantics

A new WebSocket connection begins unauthenticated. The server sends a fresh non-zero 32-byte challenge from `crypto/rand`; the client has 10 seconds to return the #50 canonical challenge response signed by its existing P-256 Kenato identity. The server reuses the existing canonical identity-key parser, identity-id hash binding and ECDSA/SHA-256 verification path. Merely naming an identity id never authenticates a connection.

A failed proof cannot replace or disconnect the current authenticated peer for that identity. A successfully authenticated replacement becomes the new routing owner first; only then is the previous peer stopped. Application frames are binary only, compression is disabled and each connection enforces the 100 KiB M4 read limit.

For an online recipient, the server prefers direct opaque delivery. The pending direct operation waits up to 5 seconds for a matching ACK from the authenticated recipient connection. A matching direct ACK lets the sender receive `SendAccepted` without durable mailbox storage. Timeout, disconnect or bounded outbound backpressure falls back to #51 mailbox custody when possible. `SendAccepted` never states which path occurred.

If ACK and fallback race, the transport checks ACK state after the durable store attempt and performs an idempotent authenticated mailbox delete so a just-committed fallback row is not intentionally stranded by an ACK that won the race. Retained reconnect deliveries remain in the mailbox until authenticated ACK; writing them to a socket never deletes them.

## Resource bounds

- M2 contact wire message: 64 KiB maximum;
- M3 session-bootstrap wire message: 128 KiB maximum;
- opaque M3 initial Olm frame: 96 KiB maximum;
- M4 ciphertext: 64 KiB maximum;
- M4 encoded envelope: 96 KiB maximum;
- M4 WebSocket application frame: 100 KiB maximum;
- M4 authenticated routing registry: at most 128 peers;
- M4 unauthenticated handshakes: at most 32 concurrently;
- M4 per-peer outbound queue: at most 4 frames;
- M4 per-peer concurrent send operations: at most 4;
- M4 global send workers: at most 128;
- M4 pending direct deliveries: at most 256 globally;
- M4 authentication deadline: 10 seconds;
- M4 direct ACK fallback deadline: 5 seconds;
- M4 mailbox: at most 500 messages / 16 MiB per recipient;
- M4 mailbox: at most 1,000 messages / 32 MiB per sender;
- M4 mailbox: at most 100,000 messages / 256 MiB globally;
- M4 delivery page: at most 50 retained envelopes;
- M4 cleanup batch: at most 1,000 expired rows;
- M4 retention: at most 72 hours from server acceptance;
- Olm public key: exactly 32 bytes;
- M3 public OTKs per signed bundle: 1..50;
- session bootstrap rows: no more than the existing 100,000-identity cap, one current row per identity;
- M2 active invites per creator: 16;
- M2/M3 request service deadline: 8 seconds;
- SQLite busy timeout: 5 seconds;
- HTTP read/write/header/idle bounds remain configured in `cmd/kenato-server`.

The mailbox enforces count/byte limits both in Go and with a SQLite `BEFORE INSERT` trigger. Physical global quotas include expired rows awaiting cleanup so delayed maintenance cannot make disk use unbounded. WSS direct-routing state is separately bounded in memory and does not grow an unbounded queue when a recipient is slow.

## Privacy boundary

The M2/M3 database persists only public identity/prekey material, monotonic publication metadata, SHA-256 invite-token hashes, invite timestamps/state, public authenticated M3 account/OTK material, and temporary redemption/session-bootstrap relationship/proof data. Raw invite tokens exist only transiently while bounded requests are processed.

The M4 mailbox persists sender/recipient routing ids, message id, acceptance/expiry timing, ciphertext-size metadata and the bounded opaque encoded envelope. It does not store user plaintext, contact display names, message semantic type, private identity/prekey material, Olm private account/OTK/session keys, or decrypted M3 plaintext.

The M4 routing process necessarily observes connection ownership and outer routing metadata while forwarding traffic. The public protocol deliberately avoids an explicit presence result, but M4 does not claim metadata privacy from the routing server itself. Message content remains opaque M3 ciphertext.

Successful creator claim deletes the temporary invite/session-bootstrap relationship immediately. Unclaimed expired state is removed by startup/hourly retention cleanup. Mailbox rows are physically deleted after recipient ACK or bounded expiry cleanup.

## Verification

From `server/`:

```sh
go mod tidy
git diff --exit-code -- go.mod go.sum
gofmt -l .
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
```

Repository verification additionally runs `scripts/verify_m4_protocol.py`, `scripts/verify_m4_mailbox.py`, and `scripts/verify_m4_transport.py`. CI builds the server for linux/amd64 and linux/arm64 and validates all current protocol schemas with `protoc`.
