# M4 Mailbox Security Review

Status: implementation review for M4 issue #51.

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

## Authentication and recipient existence

A mailbox write is accepted by the service only when:

- the authenticated sender identity exactly matches the outer envelope sender;
- the #50 envelope validation succeeds at the server acceptance time;
- the encoded envelope is within the 96 KiB bound; and
- the recipient exists according to the internal contact identity directory.

Unknown-recipient handling returns the same generic mailbox rejection class used for other non-capacity send rejection. #52 must continue to map these internal results to the coarse public M4 error contract and must not expose the internal identity lookup as an endpoint.

The mailbox database itself does not duplicate public identity bundles or contact state. Splitting the databases avoids coupling M4 retention lifecycle to destructive M2/M3 invite/bootstrap cleanup while keeping both databases local, mode 0600, SQLite WAL, and synchronous FULL.

## Duplicate and conflict behavior

The storage uniqueness key is `(sender_identity_id, message_id)`.

An exact retry is idempotent only when recipient, expiry, ciphertext length and the retained encoded envelope bytes are unchanged. Reusing the same sender/message id with different retained bytes or routing metadata is a generic conflict/rejection.

This means a lost `SendAccepted` can be retried safely without creating a second retained row, while deliberate message-id reuse cannot overwrite or retarget existing custody.

## ACK deletion

ACK deletion is bound to all three values:

- authenticated recipient identity;
- stored sender identity;
- message id.

A mismatched recipient or sender deletes nothing. An exact duplicate ACK after the row has already been deleted is harmless and remains idempotent. The mailbox never deletes a different row merely because the message id matches.

The Android-side crash-safe rule from ADR 0011 remains mandatory: #53 must not send ACK until ratchet advancement and the durable local delivery handoff/history commit are complete.

## Expiry and cleanup

A retained row is expired exactly when `now >= expires_at`. Expired rows are excluded from delivery immediately at that boundary even if physical cleanup has not yet run.

`OpenSQLiteMailboxStore` performs one bounded cleanup batch at startup. The server also performs bounded mailbox cleanup on the existing hourly retention tick. Each storage operation may additionally remove one bounded expired batch before a new insert so stale physical rows cannot accumulate indefinitely while writes continue.

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

Read paths revalidate stored routing ids, message ids, expiry, ciphertext-size metadata and envelope bounds. Malformed persisted state fails closed with `ErrMailboxCorrupt` rather than being delivered.

## Logging and privacy

No mailbox method logs plaintext, ciphertext, complete envelope bytes, message ids, sender/recipient ids, or quota usage. The server's maintenance loop emits only generic cleanup-failure text.

A compromised server still learns sender/recipient routing ids, timing, envelope size and mailbox occupancy and can retain or suppress ciphertext outside policy. M3 encryption plus the #50 authenticated inner/outer context binding prevents the mailbox from learning plaintext or silently changing the authenticated sender/recipient/message-id/expiry seen by a correct recipient.

## Scope boundary

This review covers durable mailbox persistence only. It does not add the authenticated WSS connection hub, direct online delivery, WebSocket backpressure policy, Android conversation history, or M5 calling. Those remain #52–#54 and later milestones.
