# M4 Authenticated Transport Security Review

Status: implementation review for M4 issue #52, with the #53 cross-boundary response-backpressure hardening recorded here. This review covers only the server-side authenticated WebSocket routing/direct-delivery slice. Android local history/UI and M5 calling remain out of scope.

## Trust boundary

The Go service continues to bind to loopback by default. Public deployment terminates TLS at the reviewed reverse proxy and forwards ordinary HTTP/WebSocket traffic to the loopback service. Forwarded address headers are never identity credentials.

The WebSocket endpoint is `GET /v1/messaging/ws`. Application messages are binary only. Compression is disabled and each connection applies the existing 100 KiB M4 wire-frame read limit.

## Identity authentication

A newly upgraded socket is unauthenticated. The server generates a non-zero 32-byte challenge from `crypto/rand`, binds it to that connection and gives the authentication exchange a 10-second deadline. The signed challenge lifetime remains at most 30 seconds under the #50 protocol contract.

The client response is validated against the exact challenge and expiry before signature verification. Signature verification reuses the existing canonical P-256 identity-key parser, identity-id hash binding and ECDSA/SHA-256 verifier in the contact package. Routing identity ids alone never authenticate a connection.

A failed proof has no authority over the current authenticated connection for the claimed identity. A same-identity replacement becomes active only after successful proof verification. Only then is the previous authenticated peer stopped. Tests cover both failed replacement isolation and successful replacement.

## Resource bounds

The initial #52 server limits are intentionally explicit and fail closed:

- at most 128 authenticated connections in the active routing registry;
- at most 32 unauthenticated WebSocket handshakes at once;
- at most 4 queued outbound frames per authenticated peer;
- at most 4 concurrent send operations per peer;
- at most 128 concurrent send workers globally;
- at most 256 pending direct deliveries globally;
- 100 KiB maximum WebSocket application frame;
- 10 seconds for connection authentication;
- 5 seconds for individual writes and mailbox operations;
- 5 seconds for direct-delivery ACK before durable fallback;
- retained mailbox drain remains paged at the #51 limit of 50 envelopes.

The combination keeps queued direct-routing payload state bounded. Backpressure does not grow an unbounded in-memory queue: direct delivery falls back to the #51 mailbox when durable custody can be accepted, otherwise the sender receives a coarse retry/rejection result.

Security tests exercise the unauthenticated handshake cap, authenticated registry cap, per-peer send cap, outbound backpressure and oversized-frame disconnect behavior.

## Direct delivery and ACK race

For an online recipient the server first attempts direct delivery of the opaque encrypted envelope. A pending direct record is keyed by authenticated sender plus message id and stores the exact canonical envelope bytes used for conflict detection. Exact sender retries join the existing pending result; conflicting reuse is rejected.

A matching ACK is accepted only from the authenticated recipient connection and must name the original sender plus message id. The ACK resolves the direct pending state before mailbox deletion so a healthy direct delivery is not blocked by storage latency.

If timeout, disconnect or backpressure races the recipient ACK, fallback may begin at the same time. After durable store returns, fallback checks ACK state again. If the ACK won the race, the server performs an idempotent authenticated mailbox delete so a newly committed fallback row is not intentionally stranded. Even if a later storage operation fails, #51 retention remains bounded by 72 hours and the client-side #53 design must deduplicate by the authenticated message id.

`MessagingSendAccepted` intentionally does not expose whether the recipient was online. It means either direct delivery was acknowledged or durable mailbox custody was accepted.

## Sender response backpressure and retry classification

The per-peer outbound queue is deliberately bounded, so sender result frames require an explicit failure rule. A successful durable/direct route is not allowed to become an invisible success merely because the sender's response queue is full: if `MessagingSendAccepted` cannot be encoded or enqueued, the authenticated sender peer is stopped. The Android client therefore observes disconnect and can replay the exact durable envelope after re-authentication instead of remaining indefinitely in `PENDING_ACCEPTANCE`.

The same rule applies when a send-result or ACK-error frame cannot enter the bounded response queue: the server closes the peer rather than silently dropping the only observable result. This preserves bounded memory without turning queue pressure into an ambiguous live connection.

Temporary capacity is retryable. In particular, mailbox capacity (`ErrMailboxCapacity`), server shutdown/capacity and per-peer/global send admission pressure use `RETRY_LATER`. Permanent/invariant send failures such as authenticated message-id conflict or mailbox rejection remain `SEND_REJECTED`. This distinction lets the durable Android transport reconnect/replay transient failures while continuing to fail closed on conflicting or invalid sends.

## Offline reconnect

After authentication the peer receives retained mailbox pages through the same bounded outbound queue. A mailbox row is never deleted merely because it was written to the socket. Deletion requires the authenticated recipient ACK. Disconnect therefore leaves retained state durable for retry.

The transport tracks per-peer mailbox deliveries already in flight so repeated drain wakeups do not enqueue unbounded copies of the same retained row.

## Presence and enumeration resistance

The public protocol uses coarse malformed/authentication/send/retry classes. It does not return an explicit online/offline state. Unknown recipient, offline recipient and internal mailbox outcomes are not exposed as a dedicated identity-existence or presence query.

Direct-delivery preference remains observable to the server itself because the server owns routing. M4 does not claim metadata-hiding from a compromised server. End-to-end confidentiality continues to depend on the M3 session ciphertext, including the inner sender/recipient/message-id/expiry binding defined by #50.

## WebSocket dependency

The transport uses the exact Go module `github.com/coder/websocket v1.8.15`. Compression is disabled. The server does not enable permissive origin bypass options or context takeover. The dependency is covered by the repository module lock check, Dependency Review, govulncheck and CodeQL/CI gates.

## Shutdown and lifecycle

Messaging shutdown marks routing closed, stops authenticated peers, closes in-flight handshake sockets and waits for bounded handler/send/pending work before durable stores are allowed to close. The application invokes messaging shutdown before HTTP server shutdown.

Each authenticated peer has one bounded writer path and a cancellable context. Connection replacement and shutdown use idempotent stop semantics so repeated close paths cannot panic or leave the registry pointing at an older peer.

## Verification requirements

The #52 baseline plus the #53 cross-boundary hardening require:

- `go test ./...` and `go test -race ./...` must pass;
- malformed, text and oversized WebSocket frames must fail closed;
- failed authentication must not evict an existing authenticated peer;
- successful same-identity authentication must replace the old peer;
- direct ACK, offline fallback, reconnect drain, backpressure and shutdown tests must pass;
- sender response-queue exhaustion must disconnect instead of silently losing `SendAccepted`/error state;
- transient mailbox capacity must produce `RETRY_LATER` rather than permanent `SEND_REJECTED`;
- `scripts/verify_m4_transport.py` must remain part of repository `make test`;
- all protected-branch exact-head checks must be green.
