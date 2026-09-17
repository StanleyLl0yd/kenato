#!/usr/bin/env python3
"""Pin static evidence required by the final repository-wide M4/#54 audit."""

from pathlib import Path

errors: list[str] = []


def read(path: str) -> str:
    candidate = Path(path)
    if not candidate.is_file():
        errors.append(f"missing required M4 final-audit file: {path}")
        return ""
    return candidate.read_text(encoding="utf-8")


def require(path: str, *fragments: str) -> None:
    text = read(path)
    for fragment in fragments:
        if fragment not in text:
            errors.append(f"{path}: missing required M4 final-audit evidence: {fragment}")


def forbid(path: str, *fragments: str) -> None:
    text = read(path)
    for fragment in fragments:
        if fragment in text:
            errors.append(f"{path}: stale/forbidden M4 final-audit fragment remains: {fragment}")


require(
    "server/internal/httpapi/messaging_ws_authorization_test.go",
    "TestMessagingWSSRejectsAuthenticationProofReplayAcrossConnections",
    "TestMessagingWSSRejectsAuthenticatedSenderSubstitution",
    "TestMessagingWSSUnauthorizedAckCannotResolveDirectDelivery",
    "originalPeer := wsServer.peers[string(identityID)]",
    "current != originalPeer",
    "envelope.ExpiresAtUnixSeconds = now.Add(time.Hour).Unix()",
)
require(
    "server/internal/httpapi/messaging_ack_store_race_test.go",
    "TestMessagingDirectAckRacingFallbackDeletesCommittedMailboxRow",
)
require(
    "server/internal/messaging/wire_vectors_m4_test.go",
    "TestM4ServerVisibleWireVectors",
    "m4EnvelopeVectorHex",
    "m4ClientSendVectorHex",
    "m4ServerDeliveryVectorHex",
)
require(
    "android/app/src/test/java/com/sl/kenato/messaging/MessagingWireVectorTest.kt",
    "serverVisibleWireMatchesSharedM4Vectors",
    "ENVELOPE_HEX",
    "CLIENT_SEND_HEX",
    "SERVER_DELIVERY_HEX",
)
require(
    "scripts/verify_m4_server_lifecycle.py",
    "M4 WSS shutdown must precede HTTP shutdown",
    "server failure must enter the common ordered shutdown path",
)
require(
    "scripts/verify_ci_supply_chain.py",
    "MUTATING_CARGO_LOCK",
    "generate-lockfile|update",
    "verification workflows must use committed Cargo.lock files with --locked",
)

makefile = read("Makefile")
for verifier in (
    "scripts/verify_ci_supply_chain.py",
    "scripts/verify_m4_protocol.py",
    "scripts/verify_m4_mailbox.py",
    "scripts/verify_m4_transport.py",
    "scripts/verify_m4_server_lifecycle.py",
    "scripts/verify_m4_android_messaging.py",
    "scripts/verify_m4_final_audit.py",
):
    if verifier not in makefile:
        errors.append(f"Makefile: final M4 make-test contract is missing {verifier}")

require(
    "docs/security/M4_FINAL_REPOSITORY_REVIEW.md",
    "# M4 Final Repository-Wide Security Review",
    "Status: **complete** for issue #54 / tracker #49",
    "## Mandatory second repository-wide pass — completed",
    "No new production runtime/security defect was found after those corrections",
    "no unresolved Critical/High M4 finding remains",
    "## Closure rule",
    "exact resulting `main` SHA",
    "2a3388d2898191edb9ac1277eafdcdbf780b467f",
    "M5 remains blocked",
)
require(
    "ROADMAP.md",
    "Status: **Complete** (2026-09-17; tracker #49; final verification #54).",
    "#54 final end-to-end/security verification — **complete**",
    "#59/M4.5",
)
require(
    "protocol/README.md",
    "M4 Minimal Messaging is complete across protocol/auth (#50)",
    "final repository-wide end-to-end/security verification (#54)",
    "The completed #53 implementation provides a crash-safe durable delivery handoff/journal",
)
forbid(
    "protocol/README.md",
    "#54 is the active final repository-wide end-to-end/security verification",
    "M4 is now active and begins with the authenticated minimal-messaging wire contract",
    "Therefore #53 must provide a crash-safe durable delivery handoff/journal",
)
require(
    "AGENTS.md",
    "M0–M4 are complete.",
    "#54 final repository-wide verification",
    "#59/M4.5 is the next permitted milestone",
    "Do not start M5",
)
forbid(
    "AGENTS.md",
    "M4 — Minimal Messaging is active",
    "Do not treat M4 as complete until #54",
    "#53 Android messaging/history is the current slice",
)
require(
    "CONTRIBUTING.md",
    "M4 Minimal Messaging are complete",
    "#59/M4.5 is the next permitted milestone",
    "M5 remains blocked",
)
forbid(
    "CONTRIBUTING.md",
    "M4 Minimal Messaging is active",
    "M4 Minimal Messaging has not started",
)
require(
    "docs/development/OCI_HOST.md",
    "M0–M4 are complete.",
    "#59/M4.5 is the next permitted milestone",
    "M5 remains blocked",
)
forbid(
    "docs/development/OCI_HOST.md",
    "M4 Minimal Messaging is active",
    "M4 has not started",
)
require(
    "docs/architecture/OVERVIEW.md",
    "M0–M4 are complete.",
    "#54 completed final repository-wide M4 end-to-end/security verification",
    "#59/M4.5 is the next permitted milestone",
)
forbid(
    "docs/architecture/OVERVIEW.md",
    "M4 is active in final verification",
    "#54 is the current final repository-wide M4",
)
require(
    "docs/security/THREAT_MODEL.md",
    "Status: M0–M4 complete.",
    "#50–#54 are complete",
    "#59/M4.5 is the next permitted milestone",
)
forbid(
    "docs/security/THREAT_MODEL.md",
    "M4 is active under tracker #49",
    "#54 final repository-wide M4 verification is active",
)
require(
    "docs/security/M4_ANDROID_MESSAGING_REVIEW.md",
    "Status: #53 Android messaging/history implementation is complete and was revalidated by the completed #54",
    "Issue #54 final repository-wide M4 end-to-end/security verification is complete.",
    "#59/M4.5 is the next permitted work",
)
forbid(
    "docs/security/M4_ANDROID_MESSAGING_REVIEW.md",
    "Before #53 is complete:",
    "Issue #54 remains the final repository-wide M4 end-to-end/security cleanup after #53.",
    "Issue #54 is the active final repository-wide M4 end-to-end/security cleanup.",
)

workflow = read(".github/workflows/ci.yml")
for fragment in ("cargo generate-lockfile", "cargo update"):
    if fragment in workflow:
        errors.append(f".github/workflows/ci.yml: verification must not run {fragment}")

if errors:
    raise SystemExit("\n".join(errors))

print("M4 final repository-audit evidence OK")
