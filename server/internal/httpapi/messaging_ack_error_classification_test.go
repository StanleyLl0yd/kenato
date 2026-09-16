package httpapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
)

type ackErrorMailbox struct {
	ackErr error
}

func (m *ackErrorMailbox) Store(context.Context, []byte, messaging.Envelope) error {
	return nil
}

func (m *ackErrorMailbox) Deliveries(context.Context, []byte, int) ([]messaging.MailboxDelivery, error) {
	return nil, nil
}

func (m *ackErrorMailbox) Ack(context.Context, []byte, messaging.DeliveryAck) error {
	return m.ackErr
}

func TestMessagingWSSClassifiesTransientAckFailureAsRetryLater(t *testing.T) {
	mailbox := &ackErrorMailbox{ackErr: errors.New("temporary ACK storage failure")}
	wsServer := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)
	httpServer := httptest.NewServer(newHandler(nil, nil, wsServer))
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	recipientID := testIdentity(0x21)
	senderID := testIdentity(0x22)
	peer := dialAuthenticatedPeer(t, httpServer.URL, recipientID, []byte("ok"))
	defer peer.CloseNow()
	ack := messaging.DeliveryAck{
		ProtocolVersion:  messaging.ProtocolVersion,
		SenderIdentityID: senderID,
		MessageID:        testEnvelope(senderID, recipientID, 0x23).MessageID,
	}

	writeClientFrame(t, peer, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Ack: &ack})
	frame := readServerFrame(t, peer)

	if frame.Error == nil || frame.Error.Code != messaging.MessagingErrorRetryLater {
		t.Fatalf("transient ACK failure response = %#v, want RETRY_LATER", frame)
	}
}

func TestMessagingWSSClassifiesPermanentAckRejectionAsMalformed(t *testing.T) {
	mailbox := &ackErrorMailbox{ackErr: messaging.ErrMailboxRejected}
	wsServer := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)
	httpServer := httptest.NewServer(newHandler(nil, nil, wsServer))
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	recipientID := testIdentity(0x31)
	senderID := testIdentity(0x32)
	peer := dialAuthenticatedPeer(t, httpServer.URL, recipientID, []byte("ok"))
	defer peer.CloseNow()
	ack := messaging.DeliveryAck{
		ProtocolVersion:  messaging.ProtocolVersion,
		SenderIdentityID: senderID,
		MessageID:        testEnvelope(senderID, recipientID, 0x33).MessageID,
	}

	writeClientFrame(t, peer, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Ack: &ack})
	frame := readServerFrame(t, peer)

	if frame.Error == nil || frame.Error.Code != messaging.MessagingErrorMalformed {
		t.Fatalf("permanent ACK rejection response = %#v, want MALFORMED", frame)
	}
}
