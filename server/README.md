# Kenato Server

The initial backend is a deliberately small Go service.

Current M0 surface:

- bounded HTTP server configuration;
- `GET /healthz`;
- graceful shutdown;
- no external runtime dependencies.

Planned later milestones add identity public material/prekeys, invite lifecycle, WSS routing, bounded mailbox storage, TURN credential issuance, and push wake-up integration.

The server must never require plaintext user messages, call signaling content, private identity keys, or voice content.
