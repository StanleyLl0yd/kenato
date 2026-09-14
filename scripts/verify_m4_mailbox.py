#!/usr/bin/env python3
"""Verify the M4 mailbox persistence/resource contract cannot drift silently."""

from __future__ import annotations

import sys
from pathlib import Path

errors: list[str] = []


def read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"{path}: unable to read: {error}")
        return ""


def require(path: str, text: str, fragment: str) -> None:
    if fragment not in text:
        errors.append(f"{path}: missing mailbox policy fragment {fragment!r}")


model = read("server/internal/messaging/mailbox_model.go")
for fragment in (
    "MaxMailboxBytesPerRecipient int64 = 16 * 1024 * 1024",
    "MaxMailboxMessagesPerSender       = 1_000",
    "MaxMailboxBytesPerSender    int64 = 32 * 1024 * 1024",
    "MaxMailboxMessagesGlobal          = 100_000",
    "MaxMailboxBytesGlobal       int64 = 256 * 1024 * 1024",
    "MaxMailboxDeliveryPage            = 50",
    "MaxMailboxCleanupBatch            = 1_000",
):
    require("server/internal/messaging/mailbox_model.go", model, fragment)

wire = read("server/internal/messaging/wire.go")
for fragment in (
    "func EncodeEnvelope",
    "func DecodeEnvelope",
    "MaxEnvelopeBytes",
    "validEnvelopeShape",
    "protowire.AppendTag(out, 6, protowire.BytesType)",
):
    require("server/internal/messaging/wire.go", wire, fragment)

store = read("server/internal/messaging/mailbox_sqlite.go")
for fragment in (
    "STRICT;",
    "CREATE TRIGGER IF NOT EXISTS mailbox_capacity_guard",
    "expires_at - accepted_at <= 259200",
    "ciphertext_size BETWEEN 1 AND 65536",
    "length(encoded_envelope) BETWEEN 1 AND 98304",
    "UNIQUE(sender_identity_id, message_id)",
    "16777216",
    "33554432",
    "100000",
    "268435456",
    'query.Set("_journal_mode", "WAL")',
    'query.Set("_synchronous", "FULL")',
    "0o600",
    "MaxMailboxCleanupBatch",
    "ORDER BY mailbox_id",
    "decoded, err := DecodeEnvelope(encoded)",
    "canonical, err := EncodeEnvelope(decoded)",
    "!bytes.Equal(canonical, encoded)",
):
    require("server/internal/messaging/mailbox_sqlite.go", store, fragment)

service = read("server/internal/messaging/mailbox_service.go")
for fragment in (
    "IdentityExists",
    "bytes.Equal(authenticatedSender, envelope.SenderIdentityID)",
    "ValidateEnvelopeAt(envelope, now)",
    "encodedEnvelope, err := EncodeEnvelope(envelope)",
    "MaxMailboxDeliveryPage",
    "AckMailbox",
):
    require("server/internal/messaging/mailbox_service.go", service, fragment)

directory = read("server/internal/contact/identity_directory.go")
require("server/internal/contact/identity_directory.go", directory, "func (s *SQLiteStore) IdentityExists")
require("server/internal/contact/identity_directory.go", directory, "SELECT 1 FROM identities")

main = read("server/cmd/kenato-server/main.go")
for fragment in (
    "KENATO_MAILBOX_DB_PATH",
    "OpenSQLiteMailboxStore",
    "retentionCleanupInterval   = time.Hour",
    "mailboxStore.PruneExpired",
):
    require("server/cmd/kenato-server/main.go", main, fragment)

security = read("docs/security/M4_MAILBOX_REVIEW.md")
for fragment in (
    "16 MiB",
    "32 MiB",
    "256 MiB",
    "100,000",
    "exact retry",
    "recipient existence",
    "canonical",
    "ACK",
):
    require("docs/security/M4_MAILBOX_REVIEW.md", security, fragment)

makefile = read("Makefile")
require("Makefile", makefile, "python3 scripts/verify_m4_mailbox.py")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("M4 mailbox policy OK")
