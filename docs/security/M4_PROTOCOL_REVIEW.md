# M4 Messaging Protocol Security Review

Status: M4 active, protocol/authentication slice #50.

This review covers the first M4 slice only: the wire contract, WSS identity-authentication framing, routing-envelope context, delivery acknowledgement semantics, bounds, and the client durability rule required before ACK. It does not claim that the mailbox, live WSS server, Android conversation history, or final M4 end-to-end path already exist.

## Trust boundaries

The established M1/M2 Kenato P-256 identity remains the transport-authentication trust root. M4 does not make an identity id, WebSocket URL, routing envelope, IP address, cookie, or server assertion sufficient proof of identity ownership.

The M3 vodozemac Olm session remains the content-authentication/confidentiality boundary. The server may route and temporarily retain bounded ciphertext but must never require ordinary message plaintext or private identity/session material.

## WSS authentication

Each new connection starts unauthenticated. The server generates a cryptographically random 32-byte challenge, scopes it to that connection, and gives it a lifetime of at most 30 seconds. The client signs the domain-separated canonical payload:

```text
KENATO-MESSAGING-AUTH-V1\0
|| identity_id[32]
|| challenge[32]
|| expires_at_unix_seconds:u64
```

The server verifies the signature against the already-published Kenato P-256 public key for that exact identity id. Challenge mismatch, expiry, reuse, malformed shape, unknown identity, or invalid signature fails closed. Public error behavior must not reveal whether the identity exists.

A replacement socket cannot evict the current authenticated socket until the replacement has itself authenticated successfully. This prevents an unauthenticated connection attempt from becoming a trivial disconnect primitive.

## Routing-context substitution

The server must see enough metadata to route a message, but those outer fields are not trusted end-to-end. Sender identity id, recipient identity id, random 16-byte message id, and expiry are therefore duplicated inside `MessagingPlaintext`, which is encrypted/authenticated by M3.

After decrypt, the recipient compares all four inner values with the outer envelope. A mismatch is a protocol failure and is not ACKed. This prevents a malicious relay that cannot forge the M3 ciphertext from silently:

- changing the sender or recipient label;
- changing deduplication identity;
- transplanting ciphertext to another routing context;
- extending expiry;
- making an unrelated outer ACK key refer to valid inner content.

The sender timestamp remains inner-only because it is not necessary for routing.

## Replay, duplicate and ordering behavior

M4 transport is intentionally at-least-once until authenticated ACK. Duplicate delivery after timeout, reconnect, or mailbox replay is expected. Correctness therefore cannot depend on exactly-once transport or global arrival order.

M3 owns cryptographic replay/reordering behavior. M4 adds stable message identity and endpoint-level deduplication. An outer duplicate whose ciphertext has already advanced the M3 ratchet must still be handled without generating a false delivery success solely because the transport repeated it.

## Crash consistency before ACK

There is a critical durability boundary between M3 and M4. M3 commits advanced ratchet state before returning plaintext. If Android ACKed immediately after decrypt and then crashed before recording the plaintext/message id in local conversation state, the server could delete its last copy while a later duplicate ciphertext is correctly rejected as a replay by the advanced ratchet.

Therefore the Android M4 implementation must establish a crash-safe durable delivery handoff/journal before ACK. The authenticated message identity and plaintext must be recoverable after process death. Transfer from the handoff into conversation history must be idempotent. Only after that durable boundary succeeds may the client acknowledge network delivery.

This requirement is part of the protocol contract even though its persistence implementation belongs to #53.

## Presence and enumeration privacy

`MessagingSendAccepted` intentionally does not reveal whether the recipient was online, whether direct delivery succeeded immediately, or whether the envelope entered durable mailbox custody. Generic failures similarly must not expose recipient existence or online state.

This does not make Kenato anonymous. A compromised server still observes connection timing, routing identities, message sizes, mailbox state and network metadata. The contract only avoids adding unnecessary public presence/enumeration oracles.

## Retention and acknowledgement

Direct online delivery is preferred so a successfully ACKed online message need not be durably stored. If a bounded direct attempt cannot complete, the same immutable envelope may enter durable mailbox custody.

ACK authorization is derived from the authenticated recipient connection. ACK names only the sender identity id and message id; the recipient identity comes from authenticated socket state. A valid ACK can delete only that recipient's exact retained row. Cross-recipient or mismatched ACK deletion is prohibited.

The future mailbox implementation must enforce expiry and quota transactionally. Expired messages are unusable at the expiry boundary and are deleted by bounded cleanup. Server retention after valid ACK is prohibited by the Kenato implementation contract, although a malicious server can always violate retention policy outside the guarantees a client can cryptographically enforce.

## Fixed protocol maximums

The first M4 contract fixes:

- message id: 16 random non-zero bytes;
- UTF-8 text: 16 KiB maximum;
- M4 ciphertext: 64 KiB maximum;
- encoded envelope: 96 KiB maximum;
- encoded WSS frame: 100 KiB maximum;
- message TTL: 72 hours maximum;
- auth challenge: 32 bytes, 30 seconds maximum lifetime;
- durable mailbox design bound: 500 retained messages per recipient.

Later implementation slices must add stricter operational limits for total retained bytes/rows, per-connection queues, connection counts, direct-delivery timers, retry cadence and expensive authentication work. They may reduce these maxima but must not silently raise them.

## Server-compromise properties

A malicious or compromised relay can deny service, drop/delay/reorder/duplicate traffic, retain metadata/ciphertext contrary to policy, lie about send acceptance, and correlate connection/message timing. M4 does not attempt to prevent those availability/metadata attacks.

Assuming peer/device private keys and the selected cryptographic primitives remain secure, the relay must not be able to make a correct client accept altered ordinary message plaintext or altered authenticated routing context without an M3 authentication/context failure.

## Logging and diagnostics

Implementations must not intentionally log:

- ordinary plaintext text;
- M3 ciphertext bodies;
- authentication signatures or raw challenges together with identity material in reusable diagnostic records;
- private identity/session keys;
- complete secret-bearing protocol frames.

Operational logs should use coarse result categories and bounded non-secret counters rather than payload dumps.

## Verification hooks

This slice is mechanically guarded by:

- strict `protolint` with no new M4 legacy exemptions;
- `protoc` compilation of `messaging.proto` from the repository-wide protocol target;
- matching Go and Kotlin canonical/auth/context tests;
- deterministic `KENATO-MESSAGING-AUTH-V1` test vector;
- `scripts/verify_m4_protocol.py` executed by repository-wide `make test`;
- the existing required CI, CodeQL, Dependency Review, Semgrep/Security and Gitleaks gates.

The milestone-wide `docs/security/THREAT_MODEL.md` is synchronized again during #54 after mailbox, WSS and Android persistence implementations exist, so it describes implemented rather than speculative M4 controls.
