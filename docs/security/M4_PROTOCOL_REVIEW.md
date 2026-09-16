# M4 Messaging Protocol Security Review

Status: implemented M4 protocol/authentication contract from #50, revalidated during final M4 audit #54.

This review defines the wire contract, WSS identity-authentication framing, routing-envelope context, delivery acknowledgement semantics, bounds, and the crash-safe client durability rule required before ACK. The mailbox (#51), authenticated WSS routing (#52), and Android transport/history layer (#53) are now implemented and are reviewed in their dedicated M4 documents. M5 calling remains out of scope.

## Trust boundaries

The established M1/M2 Kenato P-256 identity remains the transport-authentication trust root. M4 does not make an identity id, WebSocket URL, routing envelope, IP address, cookie, or server assertion sufficient proof of identity ownership.

The M3 vodozemac Olm session remains the content-authentication/confidentiality boundary. The server routes and may temporarily retain bounded ciphertext but never requires ordinary message plaintext or private identity/session material.

## WSS authentication

Each new connection starts unauthenticated. The server generates a cryptographically random non-zero 32-byte challenge, scopes it to that connection, and gives it a lifetime of at most 30 seconds. The client signs the domain-separated canonical payload:

```text
KENATO-MESSAGING-AUTH-V1\0
|| identity_id[32]
|| challenge[32]
|| expires_at_unix_seconds:u64
```

The server verifies the signature against the already-published Kenato P-256 public key for that exact identity id. Challenge mismatch, expiry, replay on a new connection, malformed shape, unknown identity, or invalid signature fails closed. Public error behavior does not expose a dedicated identity-existence result.

A replacement socket cannot evict the current authenticated socket until the replacement has itself authenticated successfully. The final M4 transport regressions also replay a previously valid authentication response against a fresh connection challenge and verify that the old authenticated peer retains authority.

## Routing-context substitution

The server must see enough metadata to route a message, but those outer fields are not trusted end-to-end. Sender identity id, recipient identity id, random 16-byte message id, and expiry are therefore duplicated inside `MessagingPlaintext`, which is encrypted/authenticated by M3.

After decrypt, the recipient compares all four inner values with the outer envelope. A mismatch is a protocol failure and is not ACKed. This prevents a relay that cannot forge the M3 ciphertext from silently:

- changing the sender or recipient label;
- changing deduplication identity;
- transplanting ciphertext to another routing context;
- extending expiry;
- making an unrelated outer ACK key refer to valid inner content.

The sender timestamp remains inner-only because it is not necessary for routing. Server transport additionally rejects an envelope whose outer sender differs from the authenticated WSS peer.

## Replay, duplicate and ordering behavior

M4 transport is intentionally at-least-once until authenticated ACK. Duplicate delivery after timeout, reconnect, or mailbox replay is expected. Correctness therefore does not depend on exactly-once transport or global arrival order.

M3 owns cryptographic replay/reordering behavior. Its native engine regression verifies bounded skipped-key out-of-order decryption and cryptographic replay rejection. M4 adds stable message identity and endpoint-level deduplication: an exact durable duplicate is ACKed from authenticated local history without a second ratchet advance, while reuse of the same authenticated sender/message id with different canonical envelope bytes fails closed before native decrypt.

## Crash consistency before ACK

There is a critical durability boundary between M3 and M4. M3 commits advanced ratchet state before plaintext can leave the session boundary. If Android ACKed immediately after decrypt and then crashed before recording the plaintext/message id locally, the server could delete its last copy while a later duplicate ciphertext is correctly rejected as a cryptographic replay.

The implemented Android layer therefore commits advanced ratchet state together with a bounded recoverable delivery handoff before exposing plaintext, then imports the validated plaintext/envelope identity into no-backup conversation history before network ACK eligibility. Transfer from the handoff into history is idempotent. If history import succeeds but handoff cleanup fails, an exact retry ACKs from authenticated history without decrypting again.

Outbound uses the symmetric durability rule: ratchet advancement and the exact immutable transport envelope are committed together before send. A retry or restart reuses those exact bytes and never re-encrypts the same logical message.

## Presence and enumeration privacy

`MessagingSendAccepted` intentionally does not reveal whether the recipient was online, whether direct delivery succeeded immediately, or whether the envelope entered durable mailbox custody. Generic failures similarly avoid a dedicated recipient-existence or online-state result.

This does not make Kenato anonymous. A compromised server still observes connection timing, routing identities, message sizes, mailbox state and network metadata. The contract avoids adding unnecessary public presence/enumeration oracles.

## Retention and acknowledgement

Direct online delivery is preferred so a successfully ACKed online message need not be durably stored. If a bounded direct attempt cannot complete, the same immutable envelope may enter durable mailbox custody.

ACK authorization is derived from the authenticated recipient connection. ACK names only the sender identity id and message id; the recipient identity comes from authenticated socket state. A valid ACK can delete only that recipient's exact retained row. Final M4 regressions verify that another authenticated peer cannot resolve a direct pending delivery and that the fallback Store/ACK race performs the required post-store idempotent delete.

The implemented mailbox enforces expiry and quota transactionally. Expired messages become unusable exactly at `now >= expires_at`, delivery is paged, cleanup is bounded, and ACK deletion is scoped to authenticated recipient + sender + message id.

## Fixed protocol maximums

The M4 contract fixes:

- message id: 16 random non-zero bytes;
- UTF-8 text: 16 KiB maximum;
- M4 ciphertext: 64 KiB maximum;
- encoded envelope: 96 KiB maximum;
- encoded WSS frame: 100 KiB maximum;
- message TTL: 72 hours maximum;
- auth challenge: 32 bytes, 30 seconds maximum lifetime;
- durable mailbox: 500 retained messages per recipient, with stricter byte/sender/global storage limits in #51;
- Android active staged outbound work: 32 messages, with independently bounded handoff/history stores and retry budgets.

Operational implementations may reduce these maxima but must not silently raise them without protocol/security review.

## Server-compromise properties

A malicious or compromised relay can deny service, drop/delay/reorder/duplicate traffic, retain metadata/ciphertext contrary to policy, lie about send acceptance, and correlate connection/message timing. M4 does not attempt to prevent those availability/metadata attacks.

Assuming peer/device private keys and the selected cryptographic primitives remain secure, the relay cannot make a correct client accept altered ordinary message plaintext or altered authenticated routing context without an M3 authentication/context failure.

## Logging and diagnostics

Implementations do not intentionally log:

- ordinary plaintext text;
- M3 ciphertext bodies;
- authentication signatures or raw challenges together with identity material in reusable diagnostic records;
- private identity/session keys;
- complete secret-bearing protocol frames.

Operational logs use coarse result categories rather than payload dumps. Android messaging policy additionally rejects production logging/notification/SavedState/clipboard/shared-preference sinks for conversation content.

## Canonical cross-runtime wire evidence

`docs/security/M4_TEST_VECTORS.md` contains two shared deterministic contracts:

- the domain-separated WSS authentication payload;
- fixed server-visible protobuf bytes for one canonical `Envelope`, client `send` frame and server `delivery` frame.

Go and Android encode the same golden bytes and decode the same client/server frames. This catches field-order/tag/length drift that could otherwise leave each runtime internally green while breaking interoperability.

## Verification hooks

The implemented contract is mechanically guarded by:

- strict `protolint` with no new M4 legacy exemptions and repository `protoc` compilation;
- matching Go/Kotlin auth/context tests and deterministic authentication vector;
- shared Go/Android server-visible wire golden vectors;
- M3 replay/out-of-order engine tests and Android exact-duplicate/conflicting-envelope tests;
- WSS challenge replay, sender substitution and unauthorized ACK regressions;
- `scripts/verify_m4_protocol.py` executed by repository-wide `make test`;
- mailbox, transport and Android M4 policy verifiers;
- required CI, CodeQL, Dependency Review, Semgrep/Security and Gitleaks gates.

The milestone-wide `docs/security/THREAT_MODEL.md` is synchronized during #54 against the implemented M4 system before milestone exit.
