# Kenato Server

Kenato's backend is a deliberately small Go service. M2 adds authenticated identity publication and invite/contact establishment while keeping the listener private by default and keeping all M3 session/ratchet behavior out of scope.

## Current surface

- bounded HTTP server configuration and graceful shutdown;
- `GET /healthz`;
- `POST /v1/identity/publish`;
- `POST /v1/invites`;
- `POST /v1/invites/redeem`;
- `POST /v1/invites/claim`;
- no public identity lookup/search endpoint;
- bounded Protocol Buffers request/response framing;
- strict P-256 identity/prekey/signature verification;
- SQLite/WAL persistence for public identity bundles and temporary invite lifecycle state;
- single-use 32-byte invite tokens with 24-hour expiry, stored only as SHA-256 hashes at rest;
- monotonic publication revisions with exact-replay idempotency;
- bounded identity/invite counts and a coarse pre-crypto concurrency/rate gate.

The server binds to `127.0.0.1:8080` by default. `KENATO_LISTEN_ADDR` may override the listener only for a reviewed deployment boundary. Public deployment is expected to terminate TLS in front of the loopback service; M2 development does not itself open public OCI HTTP/HTTPS ingress.

`KENATO_DB_PATH` selects the SQLite database. The default is `kenato.db` in the process working directory. Deployment should use a dedicated service-owned state directory. The main database is required to be a regular file and is restricted to mode `0600`; SQLite runs in WAL mode with foreign keys enabled and synchronous durability set to FULL.

## Privacy boundary

The M2 server persists only public identity/prekey material, monotonic publication metadata, SHA-256 invite-token hashes, invite timestamps/state, and temporary redemption relationship/proof data. Raw invite tokens exist only transiently while bounded requests are processed.

The server must never receive or store private identity/prekey keys, plaintext user messages, call signaling plaintext, voice content, contact display names, address-book data, or M3 session keys.

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

CI also builds the server for linux/amd64 and linux/arm64 with `CGO_ENABLED=0` for the ARM64 target.
