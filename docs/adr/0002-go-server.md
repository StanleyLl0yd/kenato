# ADR 0002: Go Server

Status: Accepted

## Context

The initial Kenato backend should be small enough for a low-cost VPS or Raspberry Pi-class host while supporting HTTPS/WSS routing, invite/prekey state, a bounded mailbox, TURN credential issuance, and operational metrics.

## Decision

Implement the initial backend in Go as a single `kenato-server` binary.

SQLite is the initial datastore. coturn remains a separate system service.

## Consequences

Positive:

- small operational footprint;
- straightforward concurrency model;
- simple Linux deployment;
- easy ARM64/AMD64 builds;
- no requirement for containers.

Negative:

- native/cgo dependency choices must be reviewed carefully if used;
- a single service requires internal modularity to remain maintainable.

A microservice split is explicitly deferred until measurable scaling or isolation requirements justify it.
