package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
	"github.com/coder/websocket"
)

type fakeMessagingAuthenticator struct{}

func (fakeMessagingAuthenticator) VerifyIdentitySignature(_ context.Context, identityID, payload, signature []byte) error {
	if len(identityID) != messaging.IdentityIDBytes || len(payload) == 0 || !bytes.Equal(signature, []byte("ok")) {
		return errors.New("invalid proof")
	}
	return nil
}

type fakeMessagingMailbox struct {
	mu         sync.Mutex
	stored     []messaging.Envelope
	deliveries map[string][]messaging.MailboxDelivery
	acks       []messaging.DeliveryAck
	storeErr   error
}

func newFakeMessagingMailbox() *fakeMessagingMailbox {
	return &fakeMessagingMailbox{deliveries: make(map[string][]messaging.MailboxDelivery)}
}

func (m *fakeMessagingMailbox) Store(_ context.Context, _ []byte, envelope messaging.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.storeErr != nil {
		return m.storeErr
	}
	m.stored = append(m.stored, cloneTestEnvelope(envelope))
	return nil
}

func (m *fakeMessagingMailbox) Deliveries(_ context.Context, recipient []byte, limit int) ([]messaging.MailboxDelivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.deliveries[string(recipient)]
	if len(rows) > limit {
		rows = rows[:limit]
	}
	out := make([]messaging.MailboxDelivery, len(rows))
	copy(out, rows)
	return out, nil
}

func (m *fakeMessagingMailbox) Ack(_ context.Context, recipient []byte, ack messaging.DeliveryAck) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acks = append(m.acks, messaging.DeliveryAck{
		ProtocolVersion:  ack.ProtocolVersion,
		SenderIdentityID: bytes.Clone(ack.SenderIdentityID),
		MessageID:        bytes.Clone(ack.MessageID),
	})
	rows := m.deliveries[string(recipient)]
	for i, row := range rows {
		if bytes.Equal(row.SenderIdentityID, ack.SenderIdentityID) && bytes.Equal(row.MessageID, ack.MessageID) {
			m.deliveries[string(recipient)] = append(rows[:i], rows[i+1:]...)
			break
		}
	}
	return nil
}

func (m *fakeMessagingMailbox) storedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.stored)
}

func TestMessagingWSSDirectDeliveryAckAvoidsMailbox(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	recipientID := testIdentity(0x22)
	senderID := testIdentity(0x11)
	recipient := dialAuthenticatedPeer(t, httpServer.URL, recipientID, []byte("ok"))
	defer recipient.CloseNow()
	sender := dialAuthenticatedPeer(t, httpServer.URL, senderID, []byte("ok"))
	defer sender.CloseNow()

	envelope := testEnvelope(senderID, recipientID, 0x33)
	writeClientFrame(t, sender, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	delivery := readServerFrame(t, recipient)
	if delivery.Delivery == nil || !bytes.Equal(delivery.Delivery.MessageID, envelope.MessageID) {
		t.Fatalf("unexpected direct delivery: %#v", delivery)
	}

	ack := messaging.DeliveryAck{ProtocolVersion: messaging.ProtocolVersion, SenderIdentityID: senderID, MessageID: envelope.MessageID}
	writeClientFrame(t, recipient, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Ack: &ack})
	accepted := readServerFrame(t, sender)
	if accepted.SendAccepted == nil || !bytes.Equal(accepted.SendAccepted.MessageID, envelope.MessageID) {
		t.Fatalf("unexpected sender acceptance: %#v", accepted)
	}
	if got := mailbox.storedCount(); got != 0 {
		t.Fatalf("direct ACK unexpectedly wrote %d mailbox rows", got)
	}
}

func TestMessagingWSSOfflineRecipientFallsBackToMailbox(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	senderID := testIdentity(0x11)
	recipientID := testIdentity(0x22)
	sender := dialAuthenticatedPeer(t, httpServer.URL, senderID, []byte("ok"))
	defer sender.CloseNow()

	envelope := testEnvelope(senderID, recipientID, 0x44)
	writeClientFrame(t, sender, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	accepted := readServerFrame(t, sender)
	if accepted.SendAccepted == nil || !bytes.Equal(accepted.SendAccepted.MessageID, envelope.MessageID) {
		t.Fatalf("unexpected sender acceptance: %#v", accepted)
	}
	if got := mailbox.storedCount(); got != 1 {
		t.Fatalf("offline fallback stored %d rows, want 1", got)
	}
}

func TestMessagingWSSReconnectDrainsMailboxUntilAck(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	recipientID := testIdentity(0x22)
	senderID := testIdentity(0x11)
	envelope := testEnvelope(senderID, recipientID, 0x55)
	encoded, err := messaging.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	mailbox.deliveries[string(recipientID)] = []messaging.MailboxDelivery{{
		SenderIdentityID:     bytes.Clone(senderID),
		RecipientIdentityID:  bytes.Clone(recipientID),
		MessageID:            bytes.Clone(envelope.MessageID),
		ExpiresAtUnixSeconds: envelope.ExpiresAtUnixSeconds,
		EncodedEnvelope:      encoded,
	}}

	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)
	recipient := dialAuthenticatedPeer(t, httpServer.URL, recipientID, []byte("ok"))
	defer recipient.CloseNow()

	delivery := readServerFrame(t, recipient)
	if delivery.Delivery == nil || !bytes.Equal(delivery.Delivery.MessageID, envelope.MessageID) {
		t.Fatalf("unexpected retained delivery: %#v", delivery)
	}
	ack := messaging.DeliveryAck{ProtocolVersion: messaging.ProtocolVersion, SenderIdentityID: senderID, MessageID: envelope.MessageID}
	writeClientFrame(t, recipient, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Ack: &ack})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mailbox.mu.Lock()
		remaining := len(mailbox.deliveries[string(recipientID)])
		mailbox.mu.Unlock()
		if remaining == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("mailbox ACK did not remove retained delivery")
}

func TestMessagingWSSFailedReplacementDoesNotEvictAuthenticatedPeer(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	identityID := testIdentity(0x66)
	first := dialAuthenticatedPeer(t, httpServer.URL, identityID, []byte("ok"))
	defer first.CloseNow()

	wsServer.mu.Lock()
	originalPeer := wsServer.peers[string(identityID)]
	wsServer.mu.Unlock()
	if originalPeer == nil {
		t.Fatal("authenticated peer was not registered")
	}

	failed := dialPeerExpectAuthFailure(t, httpServer.URL, identityID)
	defer failed.CloseNow()

	wsServer.mu.Lock()
	peer := wsServer.peers[string(identityID)]
	wsServer.mu.Unlock()
	if peer != originalPeer {
		t.Fatal("failed authentication replaced the existing authenticated peer")
	}

	recipientID := testIdentity(0x77)
	envelope := testEnvelope(identityID, recipientID, 0x67)
	writeClientFrame(t, first, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	accepted := readServerFrame(t, first)
	if accepted.SendAccepted == nil || !bytes.Equal(accepted.SendAccepted.MessageID, envelope.MessageID) {
		t.Fatalf("existing authenticated peer stopped routing after failed replacement: %#v", accepted)
	}
	if got := mailbox.storedCount(); got != 1 {
		t.Fatalf("existing authenticated peer did not remain active; mailbox rows = %d, want 1", got)
	}
}

func TestMessagingWSSBackpressureFallsBackToMailbox(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	s := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)
	recipientID := testIdentity(0x22)
	senderID := testIdentity(0x11)
	peer := &messagingPeer{
		identityID: bytes.Clone(recipientID),
		done:       make(chan struct{}),
		outbound:   make(chan []byte, messagingOutboundQueueDepth),
	}
	for i := 0; i < messagingOutboundQueueDepth; i++ {
		peer.outbound <- []byte{1}
	}
	s.peers[string(recipientID)] = peer

	envelope := testEnvelope(senderID, recipientID, 0x77)
	if err := s.routeEnvelope(envelope); err != nil {
		t.Fatalf("routeEnvelope: %v", err)
	}
	if got := mailbox.storedCount(); got != 1 {
		t.Fatalf("backpressure fallback stored %d rows, want 1", got)
	}
}

func TestMessagingWSSShutdownClosesAuthenticatedPeer(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	identityID := testIdentity(0x42)
	peer := dialAuthenticatedPeer(t, httpServer.URL, identityID, []byte("ok"))
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := wsServer.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	readCtx, readCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer readCancel()
	if _, _, err := peer.Read(readCtx); err == nil {
		t.Fatal("peer remained readable after messaging shutdown")
	}
	_ = peer.CloseNow()
}

func startMessagingTestServer(t *testing.T, mailbox *fakeMessagingMailbox) (*MessagingWebSocketServer, *httptest.Server) {
	t.Helper()
	wsServer := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, mailbox)
	httpServer := httptest.NewServer(newHandler(nil, nil, wsServer))
	return wsServer, httpServer
}

func shutdownMessagingTestServer(t *testing.T, wsServer *MessagingWebSocketServer, httpServer *httptest.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := wsServer.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	httpServer.Close()
}

func dialAuthenticatedPeer(t *testing.T, baseURL string, identityID, signature []byte) *websocket.Conn {
	t.Helper()
	conn := dialRawPeer(t, baseURL)
	challengeFrame := readServerFrame(t, conn)
	if challengeFrame.AuthChallenge == nil {
		t.Fatalf("missing authentication challenge: %#v", challengeFrame)
	}
	response := messaging.AuthResponse{
		ProtocolVersion:      messaging.ProtocolVersion,
		IdentityID:           bytes.Clone(identityID),
		Challenge:            bytes.Clone(challengeFrame.AuthChallenge.Challenge),
		ExpiresAtUnixSeconds: challengeFrame.AuthChallenge.ExpiresAtUnixSeconds,
		Signature:            bytes.Clone(signature),
	}
	writeClientFrame(t, conn, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, AuthResponse: &response})
	authenticated := readServerFrame(t, conn)
	if !authenticated.Authenticated {
		t.Fatalf("authentication was not confirmed: %#v", authenticated)
	}
	return conn
}

func dialPeerExpectAuthFailure(t *testing.T, baseURL string, identityID []byte) *websocket.Conn {
	t.Helper()
	conn := dialRawPeer(t, baseURL)
	challengeFrame := readServerFrame(t, conn)
	response := messaging.AuthResponse{
		ProtocolVersion:      messaging.ProtocolVersion,
		IdentityID:           bytes.Clone(identityID),
		Challenge:            bytes.Clone(challengeFrame.AuthChallenge.Challenge),
		ExpiresAtUnixSeconds: challengeFrame.AuthChallenge.ExpiresAtUnixSeconds,
		Signature:            []byte("bad"),
	}
	writeClientFrame(t, conn, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, AuthResponse: &response})
	failure := readServerFrame(t, conn)
	if failure.Error == nil || failure.Error.Code != messaging.MessagingErrorAuthenticationFailed {
		t.Fatalf("unexpected auth-failure frame: %#v", failure)
	}
	return conn
}

func dialRawPeer(t *testing.T, baseURL string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(baseURL, "http") + messagingWebSocketPath
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("websocket.Dial: %v", err)
	}
	conn.SetReadLimit(messaging.MaxWireFrameBytes)
	return conn
}

func readServerFrame(t *testing.T, conn *websocket.Conn) messaging.ServerFrame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	messageType, encoded, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read server frame: %v", err)
	}
	if messageType != websocket.MessageBinary {
		t.Fatalf("unexpected server message type: %v", messageType)
	}
	frame, err := messaging.DecodeServerFrame(encoded)
	if err != nil {
		t.Fatalf("DecodeServerFrame: %v", err)
	}
	return frame
}

func writeClientFrame(t *testing.T, conn *websocket.Conn, frame messaging.ClientFrame) {
	t.Helper()
	encoded, err := messaging.EncodeClientFrame(frame)
	if err != nil {
		t.Fatalf("EncodeClientFrame: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageBinary, encoded); err != nil {
		t.Fatalf("write client frame: %v", err)
	}
}

func testIdentity(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, messaging.IdentityIDBytes)
}

func testEnvelope(senderID, recipientID []byte, messageFill byte) messaging.Envelope {
	return messaging.Envelope{
		ProtocolVersion:      messaging.ProtocolVersion,
		SenderIdentityID:     bytes.Clone(senderID),
		RecipientIdentityID:  bytes.Clone(recipientID),
		MessageID:            bytes.Repeat([]byte{messageFill}, messaging.MessageIDBytes),
		Ciphertext:           []byte{1, 2, 3, 4},
		ExpiresAtUnixSeconds: time.Now().UTC().Add(time.Hour).Unix(),
	}
}

func cloneTestEnvelope(envelope messaging.Envelope) messaging.Envelope {
	return messaging.Envelope{
		ProtocolVersion:      envelope.ProtocolVersion,
		SenderIdentityID:     bytes.Clone(envelope.SenderIdentityID),
		RecipientIdentityID:  bytes.Clone(envelope.RecipientIdentityID),
		MessageID:            bytes.Clone(envelope.MessageID),
		Ciphertext:           bytes.Clone(envelope.Ciphertext),
		ExpiresAtUnixSeconds: envelope.ExpiresAtUnixSeconds,
	}
}
