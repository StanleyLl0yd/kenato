package httpapi

import (
	"bytes"
	"errors"
	"testing"

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
