# Kenato Server

Kenato's backend is a deliberately small Go service. M2 provides authenticated identity publication and invite/contact establishment. The current M3 slice adds authenticated asynchronous session-bootstrap state while keeping ordinary encrypted-message transport, mailbox behavior, and ratchet execution out of the server.

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
- no public identity or session-bootstrap lookup/search endpoint;
- bounded Protocol Buffers request/response framing;
- strict P-256 identity/prekey/signature verification for M2 plus P-256 authentication of M3 Olm public account material and bootstrap proofs;
- SQLite/WAL persistence for public identity bundles, public M3 Olm account material/available OTKs, and temporary invite/session-bootstrap lifecycle state;
- single-use 32-byte invite tokens with 24-hour expiry, stored only as SHA-256 hashes at rest;
- monotonic M2 publication revisions and M3 account-generation/publication-revision transitions with exact-replay idempotency;
- atomic single-use creator OTK reservation bound to the already-redeemed invite; fallback keys are not supported;
- bounded identity/invite/session-bootstrap counts and a coarse process-wide pre-crypto concurrency/rate gate shared by M2 and M3;
- expired-invite cleanup at startup and every hour; temporary M3 reservation/init rows cascade from invite deletion;
- generic public handling for missing identities so the API does not expose a dedicated identity-existence response.

The server binds to `127.0.0.1:8080` by default. `KENATO_LISTEN_ADDR` may override the listener only for a reviewed deployment boundary. Public deployment is expected to terminate TLS in front of the loopback service; this M3 development slice does not itself open public OCI HTTP/HTTPS ingress.

`KENATO_DB_PATH` selects the SQLite database. The default is `kenato.db` in the process working directory. Deployment should use a dedicated service-owned state directory. The main database is required to be a regular file and is restricted to mode `0600`; SQLite runs in WAL mode with foreign keys enabled and synchronous durability set to FULL.

The SQLite schema is versioned with `PRAGMA user_version`. M3 session bootstrap is an additive schema-v2 migration from the M2 schema-v1 database. Unknown newer schema versions fail closed. Migration tests must preserve existing M2 identity/contact state.

The built-in rate gate is intentionally process-wide: at most four concurrent gated operations and at most 600 accepted gated operations per one-minute process window. Source-aware or distributed edge limits should be implemented only together with the reviewed reverse-proxy/TLS deployment boundary rather than by trusting arbitrary forwarded-address headers in the loopback service.

## M3 bootstrap semantics

The invite redeemer is the deterministic M3 initiator and the invite creator is the responder. Each client publishes only public Olm account material: exact 32-byte Ed25519/Curve25519 identity public keys plus 1..50 public Curve25519 OTKs. The entire bundle is authenticated by the existing Kenato P-256 identity.

After normal M2 redemption, the exact redeemer can authenticate a reservation request for that still-live invite. SQLite atomically removes one creator OTK from the available pool and records the allocation against the invite token hash. Exact reservation retry receives the same key; another invite cannot receive that key. Exhaustion returns a conflict/unavailable result instead of falling back to reusable key material.

The redeemer then submits one bounded opaque Olm pre-key frame. Its P-256 submit proof binds both identity ids, the invite token, creator account generation and OTK id, redeemer account generation, Olm message type, and SHA-256 of the opaque frame. Exact submit replay is idempotent; conflicting metadata/frame bytes fail closed.

Creator-side M3 claim requires the creator P-256 proof and returns the M2 peer proof, authenticated redeemer M3 bundle, exact creator account generation/OTK allocation, opaque pre-key frame, and original redeemer submit signature. This gives the client enough information to independently re-verify the server-retained bootstrap data. The server then deletes the invite, and foreign-key cascades delete the temporary reservation/init rows in the same transaction.

Ordinary `SessionCiphertext` frames are not accepted by a server endpoint in M3. WSS routing, an offline mailbox, delivery acknowledgements/retries, conversation history and product messaging remain M4.

## Resource bounds

- M2 contact wire message: 64 KiB maximum;
- M3 session-bootstrap wire message: 128 KiB maximum;
- opaque M3 initial Olm frame: 96 KiB maximum;
- Olm public key: exactly 32 bytes;
- M3 public OTKs per signed bundle: 1..50;
- session bootstrap rows: no more than the existing 100,000-identity cap, one current row per identity;
- M2 active invites per creator: 16;
- M2/M3 request service deadline: 8 seconds;
- SQLite busy timeout: 5 seconds;
- HTTP read/write/header/idle bounds remain configured in `cmd/kenato-server`.

## Privacy boundary

The server persists only public identity/prekey material, monotonic publication metadata, SHA-256 invite-token hashes, invite timestamps/state, public authenticated M3 account/OTK material, and temporary redemption/session-bootstrap relationship/proof data. Raw invite tokens exist only transiently while bounded requests are processed.

The M3 init ciphertext is opaque to the server. No Kenato private identity/prekey key, Olm private account/OTK/session key, decrypted Olm control plaintext, application plaintext, contact display name, address-book data, call signaling plaintext, or voice content belongs in server state or logs.

Successful creator claim deletes the temporary invite/session-bootstrap relationship immediately. Unclaimed expired state is removed by explicit startup/hourly retention cleanup. Claim remains intentionally one-shot: if a successful response is lost after the server commits, it is not replayed from a retained relationship cache and a fresh invite is required.

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

CI also builds the server for linux/amd64 and linux/arm64 with `CGO_ENABLED=0` for the ARM64 target and validates all current protocol schemas with `protoc`.
