# ADR 0004: Versioned Platform-Independent Wire Protocol

Status: Accepted

## Context

Kenato will have multiple client and server releases, and later a second mobile platform. Protocol meaning must not be coupled to Kotlin or Go implementation types.

## Decision

Use a platform-independent, explicitly versioned wire protocol.

Protocol Buffers are the initial serialization format.

The server-routable envelope contains only metadata required for routing and protocol evolution; semantic user content remains inside authenticated ciphertext when server visibility is unnecessary.

## Consequences

Positive:

- Android, server, and future iOS implementations can share one contract;
- compatibility behavior can be tested independently;
- unknown versions can fail explicitly.

Negative:

- schema evolution requires discipline;
- generated-code/toolchain integration adds build complexity later.

Cryptographic session formats and test vectors will be introduced only in the milestone that defines the reviewed E2EE session protocol.
