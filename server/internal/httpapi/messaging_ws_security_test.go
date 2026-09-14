package httpapi

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
	"github.com/coder/websocket"
)

func TestMessagingWSSSuccessfulReplacementEvictsPreviousPeerAfterProof(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	identityID := testIdentity(0x31)
	first := dialAuthenticatedPeer(t, httpServer.URL, identityID, []byte("ok"))
	defer first.CloseNow()

	wsServer.mu.Lock()
	originalPeer := wsServer.peers[string(identityID)]
	wsServer.mu.Unlock()
	if originalPeer == nil {
		t.Fatal("first authenticated peer was not registered")
	}

	second := dialAuthenticatedPeer(t, httpServer.URL, identityID, []byte("ok"))
	defer second.CloseNow()

	wsServer.mu.Lock()
	currentPeer := wsServer.peers[string(identityID)]
	wsServer.mu.Unlock()
	if currentPeer == nil || currentPeer == originalPeer {
		t.Fatal("successful proof did not replace the previous authenticated peer")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := first.Read(ctx); err == nil {
		t.Fatal("previous authenticated connection remained active after successful replacement")
	}

	recipientID := testIdentity(0x32)
	envelope := testEnvelope(identityID, recipientID, 0x33)
	writeClientFrame(t, second, messaging.ClientFrame{ProtocolVersion: messaging.ProtocolVersion, Send: &envelope})
	accepted := readServerFrame(t, second)
	if accepted.SendAccepted == nil || !bytes.Equal(accepted.SendAccepted.MessageID, envelope.MessageID) {
		t.Fatalf("replacement peer did not remain usable: %#v", accepted)
	}
}

func TestMessagingWSSRejectsTextAndMalformedApplicationFrames(t *testing.T) {
	tests := []struct {
		name        string
		messageType websocket.MessageType
		payload     []byte
	}{
		{name: "text", messageType: websocket.MessageText, payload: []byte("not-binary")},
		{name: "malformed-binary", messageType: websocket.MessageBinary, payload: []byte{0xff}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mailbox := newFakeMessagingMailbox()
			wsServer, httpServer := startMessagingTestServer(t, mailbox)
			defer shutdownMessagingTestServer(t, wsServer, httpServer)

			peer := dialAuthenticatedPeer(t, httpServer.URL, testIdentity(0x41), []byte("ok"))
			defer peer.CloseNow()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := peer.Write(ctx, tc.messageType, tc.payload)
			cancel()
			if err != nil {
				t.Fatalf("write protocol violation: %v", err)
			}
			expectMessagingProtocolDisconnect(t, peer)
		})
	}
}

func TestMessagingWSSOversizedApplicationFrameDisconnectsPeer(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	peer := dialAuthenticatedPeer(t, httpServer.URL, testIdentity(0x42), []byte("ok"))
	defer peer.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err := peer.Write(ctx, websocket.MessageBinary, make([]byte, messaging.MaxWireFrameBytes+1))
	cancel()
	if err != nil {
		t.Fatalf("write oversized frame: %v", err)
	}
	expectMessagingProtocolDisconnect(t, peer)
}

func TestMessagingWSSBoundsUnauthenticatedHandshakeFlood(t *testing.T) {
	mailbox := newFakeMessagingMailbox()
	wsServer, httpServer := startMessagingTestServer(t, mailbox)
	defer shutdownMessagingTestServer(t, wsServer, httpServer)

	connections := make([]*websocket.Conn, 0, maxUnauthenticatedHandshakes)
	for i := 0; i < maxUnauthenticatedHandshakes; i++ {
		conn := dialRawPeer(t, httpServer.URL)
		connections = append(connections, conn)
	}
	defer func() {
		for _, conn := range connections {
			_ = conn.CloseNow()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(httpServer.URL, "http") + messagingWebSocketPath
	conn, response, err := websocket.Dial(ctx, url, nil)
	if conn != nil {
		_ = conn.CloseNow()
	}
	if err == nil {
		t.Fatal("handshake flood exceeded the configured unauthenticated cap")
	}
	if response == nil || response.StatusCode != 503 {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("handshake overflow status = %d, want 503", status)
	}
}

func TestMessagingWSSAuthenticatedRegistryCapacityAndReplacement(t *testing.T) {
	s := NewMessagingWebSocketServer(fakeMessagingAuthenticator{}, newFakeMessagingMailbox())
	peers := make([]*messagingPeer, 0, maxAuthenticatedConnections)
	for i := 0; i < maxAuthenticatedConnections; i++ {
		identityID := bytes.Repeat([]byte{byte(i + 1)}, messaging.IdentityIDBytes)
		peer := &messagingPeer{identityID: identityID}
		if old, err := s.registerPeer(peer); err != nil || old != nil {
			t.Fatalf("register peer %d: old=%p err=%v", i, old, err)
		}
		peers = append(peers, peer)
	}

	overflow := &messagingPeer{identityID: bytes.Repeat([]byte{0xfe}, messaging.IdentityIDBytes)}
	if _, err := s.registerPeer(overflow); !errors.Is(err, errMessagingCapacity) {
		t.Fatalf("registry overflow error = %v, want %v", err, errMessagingCapacity)
	}

	replacement := &messagingPeer{identityID: bytes.Clone(peers[0].identityID)}
	old, err := s.registerPeer(replacement)
	if err != nil {
		t.Fatalf("replacement at capacity: %v", err)
	}
	if old != peers[0] {
		t.Fatal("same-identity replacement did not return the previous authenticated peer")
	}
}

func TestMessagingWSSBoundsPerPeerSendFlood(t *testing.T) {
	peer := &messagingPeer{sendOps: make(chan struct{}, maxConcurrentSendOpsPerPeer)}
	for i := 0; i < maxConcurrentSendOpsPerPeer; i++ {
		if !peer.acquireSendOp() {
			t.Fatalf("send slot %d unexpectedly rejected", i)
		}
	}
	if peer.acquireSendOp() {
		t.Fatal("per-peer send flood exceeded the configured concurrency cap")
	}
	for i := 0; i < maxConcurrentSendOpsPerPeer; i++ {
		peer.releaseSendOp()
	}
}

func expectMessagingProtocolDisconnect(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	messageType, encoded, err := conn.Read(ctx)
	cancel()
	if err != nil {
		return
	}
	if messageType != websocket.MessageBinary {
		t.Fatalf("unexpected response message type before disconnect: %v", messageType)
	}
	frame, decodeErr := messaging.DecodeServerFrame(encoded)
	if decodeErr != nil || frame.Error == nil || frame.Error.Code != messaging.MessagingErrorMalformed {
		t.Fatalf("unexpected protocol-violation response: frame=%#v err=%v", frame, decodeErr)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("connection remained open after protocol violation")
	}
}
