#!/usr/bin/env python3
"""Verify the M4 WSS routing/resource contract cannot drift silently."""

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
        errors.append(f"{path}: missing M4 transport policy fragment {fragment!r}")


def forbid(path: str, text: str, fragment: str) -> None:
    if fragment in text:
        errors.append(f"{path}: forbidden M4 transport policy fragment {fragment!r}")


go_mod = read("server/go.mod")
require("server/go.mod", go_mod, "github.com/coder/websocket v1.8.15")

ws = read("server/internal/httpapi/messaging_ws.go")
for fragment in (
    'messagingWebSocketPath           = "/v1/messaging/ws"',
    "maxAuthenticatedConnections      = 128",
    "maxUnauthenticatedHandshakes     = 32",
    "messagingOutboundQueueDepth      = 4",
    "maxPendingDirectDeliveries       = 256",
    "maxConcurrentMessagingSendOps    = 128",
    "maxConcurrentSendOpsPerPeer      = 4",
    "messagingAuthenticationTimeout   = 10 * time.Second",
    "messagingWriteTimeout            = 5 * time.Second",
    "messagingMailboxOperationTimeout = 5 * time.Second",
    "messagingDirectAckTimeout        = 5 * time.Second",
    "CompressionMode: websocket.CompressionDisabled",
    "conn.SetReadLimit(messaging.MaxWireFrameBytes)",
    "messageType != websocket.MessageBinary",
    "challengeBytes := make([]byte, messaging.AuthChallengeBytes)",
    "io.ReadFull(s.random, challengeBytes)",
    "s.auth.VerifyIdentitySignature",
    "oldPeer, err := s.registerPeer(peer)",
    "oldPeer.stop()",
    "handshakeSlots: make(chan struct{}, maxUnauthenticatedHandshakes)",
    "outbound:        make(chan []byte, messagingOutboundQueueDepth)",
    "sendOps:         make(chan struct{}, maxConcurrentSendOpsPerPeer)",
    "len(s.peers) >= maxAuthenticatedConnections",
    "len(s.pending) == 0",
):
    require("server/internal/httpapi/messaging_ws.go", ws, fragment)
for fragment in (
    "InsecureSkipVerify",
    "OriginPatterns:",
    "CompressionContextTakeover",
):
    forbid("server/internal/httpapi/messaging_ws.go", ws, fragment)

routing_path = "server/internal/httpapi/messaging_routing.go"
routing = read(routing_path)
for fragment in (
    "bytes.Equal(peer.identityID, envelope.SenderIdentityID)",
    "messaging.ValidateEnvelopeAt(envelope, now)",
    "len(s.pending) >= maxPendingDirectDeliveries",
    "case <-pending.ackCh:",
    "case <-recipientPeer.done:",
    "case <-timer.C:",
    "return s.storeMailbox(envelope)",
    "s.ackDirect(peer.identityID, ack.SenderIdentityID, ack.MessageID)",
    "s.mailbox.Ack(ctx, peer.identityID, ack)",
    "s.mailbox.Deliveries(ctx, peer.identityID, messaging.MaxMailboxDeliveryPage)",
    "recipientPeer := s.peers[string(envelope.RecipientIdentityID)]",
    "recipientPeer.signalDrain()",
    "code := messaging.MessagingErrorRetryLater",
    "errors.Is(err, errMessagingConflict)",
    "errors.Is(err, messaging.ErrMailboxRejected)",
    "code = messaging.MessagingErrorSendRejected",
    "if err != nil || !peer.tryEnqueue(frame)",
    "peer.stop()",
):
    require(routing_path, routing, fragment)

auth = read("server/internal/contact/identity_auth.go")
for fragment in (
    "func (s *Service) VerifyIdentitySignature",
    "s.loadIdentity(ctx, identityID)",
    "signerKey(bundle.IdentityID, bundle.IdentityPublicKey)",
    "verifyP256Signature(identityKey, payload, signature)",
):
    require("server/internal/contact/identity_auth.go", auth, fragment)

main = read("server/cmd/kenato-server/main.go")
for fragment in (
    "NewMessagingWebSocketServer(contactService, mailboxService)",
    "NewHandlerWithMessaging(contactService, sessionService, messagingWS)",
    "messagingShutdownCtx, messagingShutdownCancel := context.WithTimeout",
    "messagingWS.Shutdown(messagingShutdownCtx)",
    "httpShutdownCtx, httpShutdownCancel := context.WithTimeout",
    "server.Shutdown(httpShutdownCtx)",
):
    require("server/cmd/kenato-server/main.go", main, fragment)
if main.find("messagingWS.Shutdown(messagingShutdownCtx)") > main.find("server.Shutdown(httpShutdownCtx)"):
    errors.append("server/cmd/kenato-server/main.go: WSS shutdown must precede HTTP server shutdown")

security_tests = read("server/internal/httpapi/messaging_ws_security_test.go")
for fragment in (
    "TestMessagingWSSSuccessfulReplacementEvictsPreviousPeerAfterProof",
    "TestMessagingWSSRejectsTextAndMalformedApplicationFrames",
    "TestMessagingWSSOversizedApplicationFrameDisconnectsPeer",
    "TestMessagingWSSBoundsUnauthenticatedHandshakeFlood",
    "TestMessagingWSSAuthenticatedRegistryCapacityAndReplacement",
    "TestMessagingWSSBoundsPerPeerSendFlood",
):
    require("server/internal/httpapi/messaging_ws_security_test.go", security_tests, fragment)

integration_tests = read("server/internal/httpapi/messaging_ws_test.go")
for fragment in (
    "TestMessagingWSSDirectDeliveryAckAvoidsMailbox",
    "TestMessagingWSSOfflineRecipientFallsBackToMailbox",
    "TestMessagingWSSReconnectDrainsMailboxUntilAck",
    "TestMessagingWSSFailedReplacementDoesNotEvictAuthenticatedPeer",
    "TestMessagingWSSBackpressureFallsBackToMailbox",
    "TestMessagingWSSShutdownClosesAuthenticatedPeer",
):
    require("server/internal/httpapi/messaging_ws_test.go", integration_tests, fragment)

liveness_tests = read("server/internal/httpapi/messaging_routing_liveness_test.go")
for fragment in (
    "TestMessagingMailboxStoreWakesCurrentRecipientPeer",
    "TestMessagingMailboxStoreFailureDoesNotWakeRecipientPeer",
):
    require("server/internal/httpapi/messaging_routing_liveness_test.go", liveness_tests, fragment)

response_backpressure_tests = read("server/internal/httpapi/messaging_response_backpressure_test.go")
for fragment in (
    "TestMessagingWSSSendAcceptedBackpressureDisconnectsSender",
    "TestMessagingWSSMailboxCapacityIsRetryable",
):
    require(
        "server/internal/httpapi/messaging_response_backpressure_test.go",
        response_backpressure_tests,
        fragment,
    )

classification_tests_path = "server/internal/httpapi/messaging_send_error_classification_test.go"
classification_tests = read(classification_tests_path)
for fragment in (
    "TestMessagingWSSClassifiesTransientMailboxFailureAsRetryLater",
    "TestMessagingWSSClassifiesMailboxCapacityAsRetryLater",
    "TestMessagingWSSClassifiesExplicitMailboxRejectionAsSendRejected",
    "TestMessagingWSSClassifiesMessageIDConflictAsSendRejected",
):
    require(classification_tests_path, classification_tests, fragment)

security_review = read("docs/security/M4_TRANSPORT_REVIEW.md")
for fragment in (
    "128 authenticated",
    "32 unauthenticated",
    "4 queued outbound frames",
    "256 pending",
    "100 KiB",
    "5 seconds",
    "presence",
    "replacement",
    "Sender response backpressure and retry classification",
    "SendAccepted",
    "RETRY_LATER",
    "transient storage",
    "message-id conflict",
):
    require("docs/security/M4_TRANSPORT_REVIEW.md", security_review, fragment)

makefile = read("Makefile")
require("Makefile", makefile, "python3 scripts/verify_m4_transport.py")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("M4 transport policy OK")