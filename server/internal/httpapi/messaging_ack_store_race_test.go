package httpapi

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
)

func TestMessagingDirectAckRacingFallbackDeletesCommittedMailboxRow(t *testing.T) {
	mailbox := newBlockingFallbackMailbox()
	s := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)

	senderID := testIdentity(0x61)
	recipientID := testIdentity(0x62)
	envelope := testEnvelope(senderID, recipientID, 0x63)

	// Fill the recipient queue so direct delivery immediately enters durable fallback.
	peer := &messagingPeer{
		identityID: bytes.Clone(recipientID),
		done:       make(chan struct{}),
		outbound:   make(chan []byte, messagingOutboundQueueDepth),
	}
	for i := 0; i < messagingOutboundQueueDepth; i++ {
		peer.outbound <- []byte{1}
	}
	s.peers[string(recipientID)] = peer

	routeDone := make(chan error, 1)
	go func() {
		routeDone <- s.routeEnvelope(envelope)
	}()

	<-mailbox.storeStarted

	// The authenticated recipient ACK wins while Store still owns the fallback write.
	s.ackDirect(recipientID, senderID, envelope.MessageID)
	close(mailbox.allowStore)

	if err := <-routeDone; err != nil {
		t.Fatalf("routeEnvelope: %v", err)
	}
	if got := mailbox.rowCount(); got != 0 {
		t.Fatalf("ACK/store race stranded %d mailbox rows, want 0", got)
	}
	if got := mailbox.ackCount(); got != 1 {
		t.Fatalf("fallback did %d post-store ACK deletes, want 1", got)
	}

	key := directPendingKey(senderID, envelope.MessageID)
	s.mu.Lock()
	pending := s.pending[key]
	s.mu.Unlock()
	if pending != nil {
		t.Fatal("ACK/store race left direct pending state behind")
	}
}

type blockingFallbackMailbox struct {
	mu           sync.Mutex
	rows         []messaging.Envelope
	acks         int
	storeStarted chan struct{}
	allowStore   chan struct{}
	startOnce    sync.Once
}

func newBlockingFallbackMailbox() *blockingFallbackMailbox {
	return &blockingFallbackMailbox{
		storeStarted: make(chan struct{}),
		allowStore:   make(chan struct{}),
	}
}

func (m *blockingFallbackMailbox) Store(ctx context.Context, _ []byte, envelope messaging.Envelope) error {
	m.startOnce.Do(func() { close(m.storeStarted) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.allowStore:
	}
	m.mu.Lock()
	m.rows = append(m.rows, cloneTestEnvelope(envelope))
	m.mu.Unlock()
	return nil
}

func (m *blockingFallbackMailbox) Deliveries(context.Context, []byte, int) ([]messaging.MailboxDelivery, error) {
	return nil, nil
}

func (m *blockingFallbackMailbox) Ack(_ context.Context, recipient []byte, ack messaging.DeliveryAck) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acks++
	for index, row := range m.rows {
		if bytes.Equal(row.RecipientIdentityID, recipient) &&
			bytes.Equal(row.SenderIdentityID, ack.SenderIdentityID) &&
			bytes.Equal(row.MessageID, ack.MessageID) {
			m.rows = append(m.rows[:index], m.rows[index+1:]...)
			break
		}
	}
	return nil
}

func (m *blockingFallbackMailbox) rowCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

func (m *blockingFallbackMailbox) ackCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acks
}
