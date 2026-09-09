# Kenato Server

The initial backend is a deliberately small Go service.

Current M0 surface:

- bounded HTTP server configuration;
- `GET /healthz`;
- graceful shutdown;
- no external runtime dependencies.

The server binds to `127.0.0.1:8080` by default so an M0 binary cannot accidentally expose itself on every interface. A reviewed deployment may explicitly override the listener with `KENATO_LISTEN_ADDR`, for example behind a TLS-terminating reverse proxy.

Planned later milestones add identity public material/prekeys, invite lifecycle, WSS routing, bounded mailbox storage, TURN credential issuance, and push wake-up integration.

The server must never require plaintext user messages, call signaling content, private identity keys, or voice content.
