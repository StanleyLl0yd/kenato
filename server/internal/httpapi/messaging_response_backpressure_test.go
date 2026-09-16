package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
	"github.com/coder/websocket"
)

func TestMessagingWSSSendAcceptedBackpressureDisconnectsSender(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	s := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)
	senderID := testIdentity(0x71)
	recipientID := testIdentity(0x72)
	peer := newDetachedMessagingPeer(t, senderID)

	for i := 0; i < messagingOutboundQueueDepth; i++ {
		peer.outbound <- []byte{byte(i + 1)}
	}

	s.handleSend(peer, testEnvelope(senderID, recipientID, 0x73))

	select {
	case <-peer.done:
	case <-time.After(2 * time.Second):
		t.Fatal("sender remained connected after SendAccepted could not enter the bounded outbound queue")
	}
	if got := mailbox.storedCount(); got != 1 {
		t.Fatalf("durable route stored %d rows, want 1", got)
	}
}

func TestMessagingWSSMailboxCapacityIsRetryable(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	mailbox.storeErr = messaging.ErrMailboxCapacity
	s := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)
	senderID := testIdentity(0x74)
	peer := newDetachedMessagingPeer(t, senderID)

	s.handleSend(peer, testEnvelope(senderID, testIdentity(0x75), 0x76))

	select {
	case encoded := <-peer.outbound:
		frame, err := messaging.DecodeServerFrame(encoded)
		if err != nil {
			t.Fatalf("DecodeServerFrame: %v", err)
		}
		if frame.Error == nil || frame.Error.Code != messaging.MessagingErrorRetryLater {
			t.Fatalf("mailbox capacity response = %#v, want RETRY_LATER", frame)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mailbox capacity did not produce a retryable response")
	}

	select {
	case <-peer.done:
		t.Fatal("retryable mailbox capacity unexpectedly disconnected the sender")
	default:
	}
}

func newDetachedMessagingPeer(t *testing.T, identityID []byte) *messagingPeer {
	t.Helper()
	serverConn := make(chan *websocket.Conn, 1)
	handlerErr := make(chan error, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			handlerErr <- err
			return
		}
		serverConn <- conn
		<-release
		_ = conn.CloseNow()
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	cancel()
	if err != nil {
		close(release)
		server.Close()
		t.Fatalf("dial detached messaging peer: %v", err)
	}

	var conn *websocket.Conn
	select {
	case err := <-handlerErr:
		_ = client.CloseNow()
		close(release)
		server.Close()
		t.Fatalf("accept detached messaging peer: %v", err)
	case conn = <-serverConn:
	case <-time.After(2 * time.Second):
		_ = client.CloseNow()
		close(release)
		server.Close()
		t.Fatal("timed out accepting detached messaging peer")
	}

	t.Cleanup(func() {
		_ = client.CloseNow()
		close(release)
		server.Close()
	})
	return newMessagingPeer(conn, identityID)
}
