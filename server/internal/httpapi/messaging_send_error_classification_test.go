package httpapi

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
)

func TestMessagingWSSClassifiesTransientMailboxFailureAsRetryLater(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	mailbox.storeErr = errors.New("temporary storage failure")
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	senderID := testIdentity(0x51)
	recipientID := testIdentity(0x52)
	sender := dialAuthenticatedPeer(t, httpServer.URL, senderID, []byte("ok"))
	defer sender.CloseNow()

	envelope := testEnvelope(senderID, recipientID, 0x53)
	writeClientFrame(t, sender, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	frame := readServerFrame(t, sender)

	if frame.Error == nil || frame.Error.Code != messaging.MessagingErrorRetryLater {
		t.Fatalf("transient mailbox failure response = %#v, want RETRY_LATER", frame)
	}
	if !bytes.Equal(frame.Error.MessageID, envelope.MessageID) {
		t.Fatalf("transient mailbox failure message id = %x, want %x", frame.Error.MessageID, envelope.MessageID)
	}
}

func TestMessagingWSSClassifiesMailboxCapacityAsRetryLater(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	mailbox.storeErr = messaging.ErrMailboxCapacity
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	senderID := testIdentity(0x61)
	recipientID := testIdentity(0x62)
	sender := dialAuthenticatedPeer(t, httpServer.URL, senderID, []byte("ok"))
	defer sender.CloseNow()

	envelope := testEnvelope(senderID, recipientID, 0x63)
	writeClientFrame(t, sender, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	frame := readServerFrame(t, sender)

	if frame.Error == nil || frame.Error.Code != messaging.MessagingErrorRetryLater {
		t.Fatalf("mailbox capacity response = %#v, want RETRY_LATER", frame)
	}
}

func TestMessagingWSSClassifiesExplicitMailboxRejectionAsSendRejected(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	mailbox.storeErr = messaging.ErrMailboxRejected
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	senderID := testIdentity(0x71)
	recipientID := testIdentity(0x72)
	sender := dialAuthenticatedPeer(t, httpServer.URL, senderID, []byte("ok"))
	defer sender.CloseNow()

	envelope := testEnvelope(senderID, recipientID, 0x73)
	writeClientFrame(t, sender, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	frame := readServerFrame(t, sender)

	if frame.Error == nil || frame.Error.Code != messaging.MessagingErrorSendRejected {
		t.Fatalf("explicit mailbox rejection response = %#v, want SEND_REJECTED", frame)
	}
}

func TestMessagingWSSClassifiesMessageIDConflictAsSendRejected(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	s := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)
	senderID := testIdentity(0x21)
	recipientID := testIdentity(0x22)
	envelope := testEnvelope(senderID, recipientID, 0x23)
	existing := cloneTestEnvelope(envelope)
	existing.Ciphertext = []byte{9, 9, 9, 9}
	encodedExisting, err := messaging.EncodeEnvelope(existing)
	if err != nil {
		t.Fatalf("EncodeEnvelope(existing): %v", err)
	}
	s.pending[directPendingKey(senderID, envelope.MessageID)] = &directPending{
		key:             directPendingKey(senderID, envelope.MessageID),
		encodedEnvelope: encodedExisting,
	}
	peer := &messagingPeer{
		identityID: bytes.Clone(senderID),
		done:       make(chan struct{}),
		outbound:   make(chan []byte, messagingOutboundQueueDepth),
		sendOps:    make(chan struct{}, maxConcurrentSendOpsPerPeer),
	}

	s.handleSend(peer, envelope)

	select {
	case encoded := <-peer.outbound:
		frame, decodeErr := messaging.DecodeServerFrame(encoded)
		if decodeErr != nil {
			t.Fatalf("DecodeServerFrame: %v", decodeErr)
		}
		if frame.Error == nil || frame.Error.Code != messaging.MessagingErrorSendRejected {
			t.Fatalf("message-id conflict response = %#v, want SEND_REJECTED", frame)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for message-id conflict response")
	}
}
