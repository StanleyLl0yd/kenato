#!/usr/bin/env python3
"""Verify the M4 messaging protocol/authentication contract cannot drift silently."""

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
        errors.append(f"{path}: missing M4 contract fragment {fragment!r}")


makefile = read("Makefile")
require("Makefile", makefile, "protocol/kenato/v1/messaging.proto")
require("Makefile", makefile, "python3 scripts/verify_m4_protocol.py")

protolint = read(".protolint.yaml")
if "protocol/kenato/v1/messaging.proto" in protolint:
    errors.append(".protolint.yaml: new M4 protocol must not receive legacy lint exemptions")

schema = read("protocol/kenato/v1/messaging.proto")
for fragment in (
    "message MessagingPlaintext",
    "message MessagingAuthChallenge",
    "message MessagingAuthResponse",
    "message MessagingDeliveryAck",
    "message MessagingSendAccepted",
    "message MessagingClientFrame",
    "message MessagingServerFrame",
    "Envelope send = 3;",
    "Envelope delivery = 4;",
):
    require("protocol/kenato/v1/messaging.proto", schema, fragment)

envelope = read("protocol/kenato/v1/envelope.proto")
for fragment in (
    "bytes recipient = 2;",
    "bytes message_id = 3;",
    "bytes ciphertext = 4;",
    "int64 expires_at_unix_seconds = 5;",
    "bytes sender = 6;",
):
    require("protocol/kenato/v1/envelope.proto", envelope, fragment)

go_model = read("server/internal/messaging/model.go")
for fragment in (
    "MessageIDBytes",
    "= 16",
    "MaxTextBytes",
    "16 * 1024",
    "MaxCiphertextBytes",
    "64 * 1024",
    "MaxEnvelopeBytes",
    "96 * 1024",
    "MaxWireFrameBytes",
    "100 * 1024",
    "MaxMailboxMessagesPerRecipient",
    "= 500",
    "MaxMessageTTLSeconds",
    "72 * 60 * 60",
    "MaxAuthChallengeLifetimeSeconds",
    "= 30",
):
    require("server/internal/messaging/model.go", go_model, fragment)

android_protocol = read("android/app/src/main/java/com/sl/kenato/messaging/MessagingProtocol.kt")
for fragment in (
    "MESSAGING_MESSAGE_ID_BYTES = 16",
    "MESSAGING_MAX_TEXT_BYTES = 16 * 1024",
    "MESSAGING_MAX_CIPHERTEXT_BYTES = 64 * 1024",
    "MESSAGING_MAX_ENVELOPE_BYTES = 96 * 1024",
    "MESSAGING_MAX_WIRE_FRAME_BYTES = 100 * 1024",
    "MESSAGING_MAX_MAILBOX_MESSAGES_PER_RECIPIENT = 500",
    "MESSAGING_MAX_TTL_SECONDS = 72L * 60L * 60L",
    "MESSAGING_MAX_AUTH_CHALLENGE_LIFETIME_SECONDS = 30L",
):
    require(
        "android/app/src/main/java/com/sl/kenato/messaging/MessagingProtocol.kt",
        android_protocol,
        fragment,
    )

canonical_go = read("server/internal/messaging/canonical.go")
for fragment in (
    "KENATO-MESSAGING-AUTH-V1",
    "SenderIdentityID",
    "RecipientIdentityID",
    "MessageID",
    "ExpiresAtUnixSeconds",
):
    require("server/internal/messaging/canonical.go", canonical_go, fragment)

for fragment in (
    "KENATO-MESSAGING-AUTH-V1",
    "senderIdentityId",
    "recipientIdentityId",
    "messageId",
    "expiresAtEpochSeconds",
):
    require(
        "android/app/src/main/java/com/sl/kenato/messaging/MessagingProtocol.kt",
        android_protocol,
        fragment,
    )

for path in (
    "docs/adr/0011-m4-minimal-messaging.md",
    "docs/security/M4_TEST_VECTORS.md",
    "docs/security/M4_PROTOCOL_REVIEW.md",
):
    text = read(path)
    require(path, text, "KENATO-MESSAGING-AUTH-V1")

security_review = read("docs/security/M4_PROTOCOL_REVIEW.md")
for fragment in (
    "Crash consistency before ACK",
    "Presence and enumeration privacy",
    "Routing-context substitution",
):
    require("docs/security/M4_PROTOCOL_REVIEW.md", security_review, fragment)

roadmap = read("ROADMAP.md")
require("ROADMAP.md", roadmap, "Status: **Active**")
require("ROADMAP.md", roadmap, "#49")

protocol_readme = read("protocol/README.md")
require("protocol/README.md", protocol_readme, "## M4 minimal messaging")
require("protocol/README.md", protocol_readme, "KENATO-MESSAGING-AUTH-V1")
require("protocol/README.md", protocol_readme, "16-byte")
require("protocol/README.md", protocol_readme, "72 hours")

architecture = read("docs/architecture/OVERVIEW.md")
require("docs/architecture/OVERVIEW.md", architecture, "M4 is active")
require("docs/architecture/OVERVIEW.md", architecture, "crash-safe durable delivery handoff")

threat_model = read("docs/security/THREAT_MODEL.md")
for fragment in (
    "M4 is active under tracker #49",
    "M4 WSS authentication",
    "M4 transport is intentionally at-least-once",
    "crash-safe durable delivery handoff",
    "MessagingSendAccepted",
):
    require("docs/security/THREAT_MODEL.md", threat_model, fragment)

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("M4 messaging protocol policy OK")
