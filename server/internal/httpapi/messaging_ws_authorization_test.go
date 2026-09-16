package httpapi

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
)

func TestMessagingWSSRejectsAuthenticationProofReplayAcrossConnections(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	firstChallengeBytes := bytes.Repeat([]byte{0x11}, messaging.AuthChallengeBytes)
	secondChallengeBytes := bytes.Repeat([]byte{0x22}, messaging.AuthChallengeBytes)
	randomBytes := append(bytes.Clone(firstChallengeBytes), secondChallengeBytes...)
	mailbox := newFakeMessagingMailbox()
	wsServer := newMessagingWebSocketServer(
		fakeMessagingAuthenticator{},
		mailbox,
		func() time.Time { return now },
		bytes.NewReader(randomBytes),
	)
	httpServer := httptest.NewServer(newHandler(nil, nil, wsServer))
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	identityID := testIdentity(0x31)
	first := dialRawPeer(t, httpServer.URL)
	defer first.CloseNow()
	firstChallenge := readServerFrame(t, first)
	if firstChallenge.AuthChallenge == nil || !bytes.Equal(firstChallenge.AuthChallenge.Challenge, firstChallengeBytes) {
		t.Fatalf("unexpected first challenge: %#v", firstChallenge)
	}
	oldResponse := messaging.AuthResponse{
		ProtocolVersion:      messaging.ProtocolVersion,
		IdentityID:           bytes.Clone(identityID),
		Challenge:            bytes.Clone(firstChallenge.AuthChallenge.Challenge),
		ExpiresAtUnixSeconds: firstChallenge.AuthChallenge.ExpiresAtUnixSeconds,
		Signature:            []byte("ok"),
	}
	writeClientFrame(t, first, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, AuthResponse: &oldResponse})
	if authenticated := readServerFrame(t, first); !authenticated.Authenticated {
		t.Fatalf("first authentication was not confirmed: %#v", authenticated)
	}

	second := dialRawPeer(t, httpServer.URL)
	defer second.CloseNow()
	secondChallenge := readServerFrame(t, second)
	if secondChallenge.AuthChallenge == nil || !bytes.Equal(secondChallenge.AuthChallenge.Challenge, secondChallengeBytes) {
		t.Fatalf("unexpected second challenge: %#v", secondChallenge)
	}
	if bytes.Equal(secondChallenge.AuthChallenge.Challenge, oldResponse.Challenge) {
		t.Fatal("test fixture reused the first connection challenge")
	}

	writeClientFrame(t, second, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, AuthResponse: &oldResponse})
	failure := readServerFrame(t, second)
	if failure.Error == nil || failure.Error.Code != messaging.MessagingErrorAuthenticationFailed {
		t.Fatalf("replayed authentication proof was not rejected: %#v", failure)
	}

	wsServer.mu.Lock()
	current := wsServer.peers[string(identityID)]
	wsServer.mu.Unlock()
	if current == nil {
		t.Fatal("replayed proof displaced the existing authenticated peer")
	}

	recipientID := testIdentity(0x32)
	envelope := testEnvelope(identityID, recipientID, 0x33)
	writeClientFrame(t, first, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	accepted := readServerFrame(t, first)
	if accepted.SendAccepted == nil || !bytes.Equal(accepted.SendAccepted.MessageID, envelope.MessageID) {
		t.Fatalf("existing authenticated peer stopped routing after replay attempt: %#v", accepted)
	}
}

func TestMessagingWSSRejectsAuthenticatedSenderSubstitution(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	attackerID := testIdentity(0x41)
	victimID := testIdentity(0x42)
	recipientID := testIdentity(0x43)
	attacker := dialAuthenticatedPeer(t, httpServer.URL, attackerID, []byte("ok"))
	defer attacker.CloseNow()

	envelope := testEnvelope(victimID, recipientID, 0x44)
	writeClientFrame(t, attacker, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	failure := readServerFrame(t, attacker)
	if failure.Error == nil || failure.Error.Code != messaging.MessagingErrorSendRejected {
		t.Fatalf("sender substitution was not rejected: %#v", failure)
	}
	if got := mailbox.storedCount(); got != 0 {
		t.Fatalf("sender substitution reached mailbox persistence: rows=%d", got)
	}
}

func TestMessagingWSSUnauthorizedAckCannotResolveDirectDelivery(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	senderID := testIdentity(0x51)
	recipientID := testIdentity(0x52)
	attackerID := testIdentity(0x53)
	sender := dialAuthenticatedPeer(t, httpServer.URL, senderID, []byte("ok"))
	defer sender.CloseNow()
	recipient := dialAuthenticatedPeer(t, httpServer.URL, recipientID, []byte("ok"))
	defer recipient.CloseNow()
	attacker := dialAuthenticatedPeer(t, httpServer.URL, attackerID, []byte("ok"))
	defer attacker.CloseNow()

	envelope := testEnvelope(senderID, recipientID, 0x54)
	writeClientFrame(t, sender, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	delivery := readServerFrame(t, recipient)
	if delivery.Delivery == nil || !bytes.Equal(delivery.Delivery.MessageID, envelope.MessageID) {
		t.Fatalf("unexpected direct delivery: %#v", delivery)
	}

	ack := messaging.DeliveryAck{
		ProtocolVersion:  messaging.ProtocolVersion,
		SenderIdentityID: bytes.Clone(senderID),
		MessageID:        bytes.Clone(envelope.MessageID),
	}
	writeClientFrame(t, attacker, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Ack: &ack})

	deadline := time.Now().Add(time.Second)
	for {
		mailbox.mu.Lock()
		ackCalls := len(mailbox.acks)
		mailbox.mu.Unlock()
		if ackCalls > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("unauthorized ACK was not processed")
		}
		time.Sleep(time.Millisecond)
	}

	key := directPendingKey(senderID, envelope.MessageID)
	wsServer.mu.Lock()
	pending := wsServer.pending[key]
	wsServer.mu.Unlock()
	if pending == nil {
		t.Fatal("unauthorized ACK removed the direct pending delivery")
	}
	if pending.isAcked() {
		t.Fatal("unauthorized ACK resolved the direct pending delivery")
	}

	writeClientFrame(t, recipient, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Ack: &ack})
	accepted := readServerFrame(t, sender)
	if accepted.SendAccepted == nil || !bytes.Equal(accepted.SendAccepted.MessageID, envelope.MessageID) {
		t.Fatalf("authorized recipient ACK did not resolve delivery: %#v", accepted)
	}
	if got := mailbox.storedCount(); got != 0 {
		t.Fatalf("authorized direct ACK unexpectedly wrote mailbox rows: %d", got)
	}
}
