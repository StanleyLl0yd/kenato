# M4 Mailbox Security Review

Status: implemented mailbox review for M4 issue #51, revalidated during final M4 audit #54.

The M4 mailbox stores only opaque encrypted envelopes and the routing/timing metadata required to deliver and delete them. It is a separate SQLite/WAL durability boundary from the M2/M3 contact/bootstrap database; recipient existence is checked only through an internal identity-directory interface and no public user lookup endpoint is added.

## Retention and resource bounds

The retained mailbox is intentionally bounded at several levels:

- at most 500 retained messages and 16 MiB of encoded envelopes per recipient;
- at most 1,000 retained messages and 32 MiB per sender across recipients;
- at most 100,000 retained messages and 256 MiB globally;
- each ciphertext remains bounded to 64 KiB and each encoded envelope to 96 KiB;
- message lifetime is at most 72 hours from server acceptance;
- delivery reads return at most 50 messages per page;
- expiry cleanup deletes at most 1,000 rows in one storage batch.

The byte limits are deliberately stricter than the theoretical count multiplied by the maximum envelope size. This prevents a sender from converting count-only limits into a practical disk-exhaustion primitive with oversized opaque frames.

Both service code and a SQLite `BEFORE INSERT` trigger enforce count/byte capacity. The trigger is the storage-level backstop if a future caller bypasses the normal service quota check.

## Authentication, canonical bytes, and recipient existence

A mailbox write is accepted by the service only when:

- the authenticated sender identity exactly matches the outer envelope sender;
- the #50 envelope validation succeeds at the server acceptance time;
- the recipient exists according to the internal contact identity directory; and
- the mailbox itself produces the canonical protobuf envelope bytes that it persists.

The storage interface rechecks that a `MailboxRecord` contains exactly the canonical encoding of its structured envelope. Callers therefore cannot supply one routing envelope for validation and unrelated raw bytes for later delivery. On read, the mailbox decodes the retained envelope, re-encodes it canonically, and compares sender, recipient, message id, expiry and ciphertext length against the indexed row metadata before returning any delivery. It also revalidates persisted `accepted_at` and the maximum 72-hour acceptance-to-expiry window, rather than relying only on SQLite `CHECK` constraints. Unknown/noncanonical or mismatched retained bytes/metadata fail closed as corrupt state.

Unknown-recipient handling returns the same generic mailbox rejection class used for other non-capacity send rejection. The implemented #52 transport maps internal mailbox outcomes to the coarse public M4 error contract and exposes no identity lookup endpoint.

The mailbox database itself does not duplicate public identity bundles or contact state. Splitting the databases avoids coupling M4 retention lifecycle to destructive M2/M3 invite/bootstrap cleanup while keeping both databases local, mode 0600, SQLite WAL, and synchronous FULL.

## Duplicate and conflict behavior

The storage uniqueness key is `(sender_identity_id, message_id)`.

An exact retry is idempotent only when recipient, expiry, ciphertext length and the retained canonical envelope bytes are unchanged. Reusing the same sender/message id with different retained bytes or routing metadata is a generic conflict/rejection.

This means a lost `SendAccepted` can be retried safely without creating a second retained row, while deliberate message-id reuse cannot overwrite or retarget existing custody.

## ACK deletion

ACK deletion is bound to all three values:

- authenticated recipient identity;
- stored sender identity;
- message id.

A mismatched recipient or sender deletes nothing. An exact duplicate ACK after the row has already been deleted is harmless and remains idempotent. The mailbox never deletes a different row merely because the message id matches.

The Android #53 implementation enforces the ADR 0011 crash-safe rule: it does not make an ACK eligible until ratchet advancement and the recoverable local delivery handoff/history commit are durable. The #52/#54 transport regressions additionally verify that another authenticated WSS peer cannot resolve the intended recipient's direct pending delivery.

## Expiry and cleanup

A retained row is expired exactly when `now >= expires_at`. Expired rows are excluded from delivery immediately at that boundary even if physical cleanup has not yet run.

`OpenSQLiteMailboxStore` performs one bounded cleanup batch at startup. The server also performs bounded mailbox cleanup on the hourly retention tick. Contact/invite cleanup and mailbox cleanup use separate bounded timeout contexts so failure or timeout in one retention domain does not cancel the other. Each storage operation may additionally remove one bounded expired batch before a new insert so stale physical rows cannot accumulate indefinitely while writes continue.

The physical global count/byte quotas include rows awaiting cleanup. This keeps disk use bounded even if cleanup is delayed or repeatedly interrupted.

## Persistence and malformed state

The mailbox database requires:

- a regular-file path restricted to mode 0600;
- SQLite WAL mode;
- synchronous FULL durability;
- STRICT tables;
- a schema version that fails closed on unknown newer versions;
- field-length/expiry/ciphertext/envelope checks in the schema;
- indexes for recipient delivery, sender quota accounting, and expiry cleanup.

Read paths revalidate stored routing ids, message ids, acceptance/expiry metadata, ciphertext-size metadata and envelope bounds. Malformed persisted state fails closed with `ErrMailboxCorrupt` rather than being delivered.

## Logging and privacy

No mailbox method logs plaintext, ciphertext, complete envelope bytes, message ids, sender/recipient ids, or quota usage. The server's maintenance loop emits only generic cleanup-failure text.

A compromised server still learns sender/recipient routing ids, timing, envelope size and mailbox occupancy and can retain or suppress ciphertext outside policy. M3 encryption plus the #50 authenticated inner/outer context binding prevents the mailbox from learning plaintext or silently changing the authenticated sender/recipient/message-id/expiry seen by a correct recipient.

## Verification record

The #51 implementation is covered by explicit tests for restart durability, exact retry/conflict handling, exact expiry boundaries, bounded cleanup, quotas under concurrency, malformed/noncanonical persisted state, SQLite path/mode/schema hardening, canonical envelope binding, persisted acceptance-window corruption, and ACK scoping. Repository policy verification pins the storage/resource/canonicalization and independent-retention-timeout invariants.

Final #54 review rechecked the storage/service paths against the live transport and found no additional mailbox persistence defect. The direct-delivery fallback/ACK race is covered at the transport boundary: if ACK wins while fallback Store is committing, the server performs the post-store idempotent delete so the newly committed row is not intentionally stranded.

## Scope boundary

This document reviews durable mailbox persistence. Authenticated WSS/direct delivery and Android conversation history are implemented and reviewed in `M4_TRANSPORT_REVIEW.md` and `M4_ANDROID_MESSAGING_REVIEW.md`; the final cross-component audit is #54. M5 calling remains out of scope.
