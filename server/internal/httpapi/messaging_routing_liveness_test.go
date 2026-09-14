package httpapi

import (
	"errors"
	"testing"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
)

func TestMessagingMailboxStoreWakesCurrentRecipientPeer(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	s := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)
	senderID := testIdentity(0x71)
	recipientID := testIdentity(0x72)
	peer := &messagingPeer{
		identityID: recipientID,
		done:       make(chan struct{}),
		wakeDrain:  make(chan struct{}, 1),
	}
	s.peers[string(recipientID)] = peer

	envelope := testEnvelope(senderID, recipientID, 0x73)
	if err := s.storeMailbox(envelope); err != nil {
		t.Fatalf("storeMailbox: %v", err)
	}
	select {
	case <-peer.wakeDrain:
	default:
		t.Fatal("successful mailbox fallback did not wake the current recipient peer")
	}
}

func TestMessagingMailboxStoreFailureDoesNotWakeRecipientPeer(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	mailbox.storeErr = errors.New("store failed")
	s := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)
	senderID := testIdentity(0x81)
	recipientID := testIdentity(0x82)
	peer := &messagingPeer{
		identityID: recipientID,
		done:       make(chan struct{}),
		wakeDrain:  make(chan struct{}, 1),
	}
	s.peers[string(recipientID)] = peer

	envelope := messaging.Envelope(testEnvelope(senderID, recipientID, 0x83))
	if err := s.storeMailbox(envelope); err == nil {
		t.Fatal("storeMailbox unexpectedly succeeded")
	}
	select {
	case <-peer.wakeDrain:
		t.Fatal("failed mailbox fallback woke recipient peer without durable custody")
	default:
	}
}
