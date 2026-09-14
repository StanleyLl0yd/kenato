package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
	"github.com/coder/websocket"
)

const (
	messagingWebSocketPath           = "/v1/messaging/ws"
	maxAuthenticatedConnections      = 128
	maxUnauthenticatedHandshakes     = 32
	messagingOutboundQueueDepth      = 4
	maxPendingDirectDeliveries       = 256
	maxConcurrentMessagingSendOps    = 128
	maxConcurrentSendOpsPerPeer      = 4
	messagingAuthenticationTimeout   = 10 * time.Second
	messagingWriteTimeout            = 5 * time.Second
	messagingMailboxOperationTimeout = 5 * time.Second
	messagingDirectAckTimeout        = 5 * time.Second
	messagingPingInterval            = 30 * time.Second
	messagingPingTimeout             = 5 * time.Second
)

var (
	errMessagingServerClosed = errors.New("messaging server closed")
	errMessagingCapacity     = errors.New("messaging server capacity reached")
	errMessagingConflict     = errors.New("messaging message id conflict")
)

type messagingIdentityAuthenticator interface {
	VerifyIdentitySignature(context.Context, []byte, []byte, []byte) error
}

type messagingMailbox interface {
	Store(context.Context, []byte, messaging.Envelope) error
	Deliveries(context.Context, []byte, int) ([]messaging.MailboxDelivery, error)
	Ack(context.Context, []byte, messaging.DeliveryAck) error
}

// MessagingWebSocketServer owns authenticated M4 WebSocket connections and
// their bounded direct-delivery state. TLS terminates at the reviewed reverse
// proxy; this handler never treats forwarded headers as identity credentials.
type MessagingWebSocketServer struct {
	auth    messagingIdentityAuthenticator
	mailbox messagingMailbox
	clock   func() time.Time
	random  io.Reader

	handshakeSlots chan struct{}
	sendSlots      chan struct{}

	mu          sync.Mutex
	closed      bool
	handlers    int
	sendWorkers int
	handshakes  map[*websocket.Conn]struct{}
	peers       map[string]*messagingPeer
	pending     map[string]*directPending
}

func NewMessagingWebSocketServer(auth messagingIdentityAuthenticator, mailbox messagingMailbox) *MessagingWebSocketServer {
	return newMessagingWebSocketServer(auth, mailbox, time.Now, rand.Reader)
}

func newMessagingWebSocketServer(auth messagingIdentityAuthenticator, mailbox messagingMailbox, clock func() time.Time, random io.Reader) *MessagingWebSocketServer {
	return &MessagingWebSocketServer{
		auth:           auth,
		mailbox:        mailbox,
		clock:          clock,
		random:         random,
		handshakeSlots: make(chan struct{}, maxUnauthenticatedHandshakes),
		sendSlots:      make(chan struct{}, maxConcurrentMessagingSendOps),
		handshakes:     make(map[*websocket.Conn]struct{}),
		peers:          make(map[string]*messagingPeer),
		pending:        make(map[string]*directPending),
	}
}

func (s *MessagingWebSocketServer) register(mux *http.ServeMux) {
	if s != nil {
		mux.HandleFunc("GET "+messagingWebSocketPath, s.handle)
	}
}

func (s *MessagingWebSocketServer) handle(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.auth == nil || s.mailbox == nil || s.clock == nil || s.random == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if !s.beginHandler() {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer s.endHandler()

	if !s.acquireHandshakeSlot() {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	handshakeHeld := true
	defer func() {
		if handshakeHeld {
			s.releaseHandshakeSlot()
		}
	}()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(messaging.MaxWireFrameBytes)

	if !s.trackHandshake(conn) {
		return
	}
	trackedHandshake := true
	defer func() {
		if trackedHandshake {
			s.untrackHandshake(conn)
		}
	}()

	identityID, err := s.authenticate(conn)
	if err != nil {
		s.writeImmediateError(conn, messaging.MessagingErrorAuthenticationFailed, nil)
		return
	}

	peer := newMessagingPeer(conn, identityID)
	oldPeer, err := s.registerPeer(peer)
	if err != nil {
		s.writeImmediateError(conn, messaging.MessagingErrorRetryLater, nil)
		return
	}
	if oldPeer != nil {
		oldPeer.stop()
	}

	s.untrackHandshake(conn)
	trackedHandshake = false
	s.releaseHandshakeSlot()
	handshakeHeld = false

	defer func() {
		s.unregisterPeer(peer)
		peer.stop()
		peer.workers.Wait()
	}()

	peer.workers.Add(2)
	go func() {
		defer peer.workers.Done()
		s.runPeerWriter(peer)
	}()
	go func() {
		defer peer.workers.Done()
		s.runMailboxDrain(peer)
	}()

	authenticatedFrame, err := messaging.EncodeServerFrame(messaging.ServerFrame{
		ProtocolVersion: messaging.ProtocolVersion,
		Authenticated:   true,
	})
	if err != nil || !peer.tryEnqueue(authenticatedFrame) {
		return
	}
	peer.signalDrain()

	s.readPeer(peer)
}

func (s *MessagingWebSocketServer) authenticate(conn *websocket.Conn) ([]byte, error) {
	authCtx, cancel := context.WithTimeout(context.Background(), messagingAuthenticationTimeout)
	defer cancel()

	challenge, err := s.newChallenge()
	if err != nil {
		return nil, err
	}
	challengeFrame, err := messaging.EncodeServerFrame(messaging.ServerFrame{
		ProtocolVersion: messaging.ProtocolVersion,
		AuthChallenge:   &challenge,
	})
	if err != nil {
		return nil, err
	}
	if err := conn.Write(authCtx, websocket.MessageBinary, challengeFrame); err != nil {
		return nil, err
	}

	messageType, encoded, err := conn.Read(authCtx)
	if err != nil || messageType != websocket.MessageBinary {
		return nil, errors.New("messaging authentication frame rejected")
	}
	frame, err := messaging.DecodeClientFrame(encoded)
	if err != nil || frame.AuthResponse == nil || frame.Send != nil || frame.Ack != nil {
		return nil, errors.New("messaging authentication frame rejected")
	}
	now := s.clock().UTC().Unix()
	if err := messaging.ValidateAuthResponseForChallenge(*frame.AuthResponse, challenge, now); err != nil {
		return nil, err
	}
	payload, err := messaging.AuthPayload(frame.AuthResponse.IdentityID, frame.AuthResponse.Challenge, frame.AuthResponse.ExpiresAtUnixSeconds)
	if err != nil {
		return nil, err
	}
	if err := s.auth.VerifyIdentitySignature(authCtx, frame.AuthResponse.IdentityID, payload, frame.AuthResponse.Signature); err != nil {
		return nil, errors.New("messaging authentication failed")
	}
	return bytes.Clone(frame.AuthResponse.IdentityID), nil
}

func (s *MessagingWebSocketServer) newChallenge() (messaging.AuthChallenge, error) {
	now := s.clock().UTC().Unix()
	if now < 0 || now > math.MaxInt64-messaging.MaxAuthChallengeLifetimeSeconds {
		return messaging.AuthChallenge{}, errors.New("messaging clock is outside the supported range")
	}
	challengeBytes := make([]byte, messaging.AuthChallengeBytes)
	for attempts := 0; attempts < 4; attempts++ {
		if _, err := io.ReadFull(s.random, challengeBytes); err != nil {
			return messaging.AuthChallenge{}, err
		}
		if !allZeroBytes(challengeBytes) {
			return messaging.AuthChallenge{
				ProtocolVersion:      messaging.ProtocolVersion,
				Challenge:            bytes.Clone(challengeBytes),
				ExpiresAtUnixSeconds: now + messaging.MaxAuthChallengeLifetimeSeconds,
			}, nil
		}
	}
	return messaging.AuthChallenge{}, errors.New("messaging random source returned an invalid challenge")
}

func (s *MessagingWebSocketServer) readPeer(peer *messagingPeer) {
	for {
		messageType, encoded, err := peer.conn.Read(peer.ctx)
		if err != nil {
			return
		}
		if messageType != websocket.MessageBinary {
			s.enqueueError(peer, messaging.MessagingErrorMalformed, nil)
			return
		}
		frame, err := messaging.DecodeClientFrame(encoded)
		if err != nil || frame.AuthResponse != nil {
			s.enqueueError(peer, messaging.MessagingErrorMalformed, nil)
			return
		}
		switch {
		case frame.Send != nil:
			s.handleSend(peer, *frame.Send)
		case frame.Ack != nil:
			s.handleAck(peer, *frame.Ack)
		default:
			s.enqueueError(peer, messaging.MessagingErrorMalformed, nil)
			return
		}
	}
}

func (s *MessagingWebSocketServer) runPeerWriter(peer *messagingPeer) {
	ticker := time.NewTicker(messagingPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-peer.done:
			return
		case frame := <-peer.outbound:
			ctx, cancel := context.WithTimeout(peer.ctx, messagingWriteTimeout)
			err := peer.conn.Write(ctx, websocket.MessageBinary, frame)
			cancel()
			if err != nil {
				peer.stop()
				return
			}
			peer.signalDrain()
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(peer.ctx, messagingPingTimeout)
			err := peer.conn.Ping(ctx)
			cancel()
			if err != nil {
				peer.stop()
				return
			}
		}
	}
}

func (s *MessagingWebSocketServer) writeImmediateError(conn *websocket.Conn, code messaging.MessagingErrorCode, messageID []byte) {
	frame, err := messaging.EncodeServerFrame(messaging.ServerFrame{
		ProtocolVersion: messaging.ProtocolVersion,
		Error: &messaging.MessagingError{
			ProtocolVersion: messaging.ProtocolVersion,
			Code:            code,
			MessageID:       bytes.Clone(messageID),
		},
	})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), messagingWriteTimeout)
	defer cancel()
	_ = conn.Write(ctx, websocket.MessageBinary, frame)
}

func (s *MessagingWebSocketServer) enqueueError(peer *messagingPeer, code messaging.MessagingErrorCode, messageID []byte) bool {
	frame, err := messaging.EncodeServerFrame(messaging.ServerFrame{
		ProtocolVersion: messaging.ProtocolVersion,
		Error: &messaging.MessagingError{
			ProtocolVersion: messaging.ProtocolVersion,
			Code:            code,
			MessageID:       bytes.Clone(messageID),
		},
	})
	return err == nil && peer.tryEnqueue(frame)
}

func (s *MessagingWebSocketServer) beginHandler() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.handlers++
	return true
}

func (s *MessagingWebSocketServer) endHandler() {
	s.mu.Lock()
	if s.handlers > 0 {
		s.handlers--
	}
	s.mu.Unlock()
}

func (s *MessagingWebSocketServer) acquireHandshakeSlot() bool {
	select {
	case s.handshakeSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *MessagingWebSocketServer) releaseHandshakeSlot() {
	select {
	case <-s.handshakeSlots:
	default:
	}
}

func (s *MessagingWebSocketServer) trackHandshake(conn *websocket.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.handshakes[conn] = struct{}{}
	return true
}

func (s *MessagingWebSocketServer) untrackHandshake(conn *websocket.Conn) {
	s.mu.Lock()
	delete(s.handshakes, conn)
	s.mu.Unlock()
}

func (s *MessagingWebSocketServer) registerPeer(peer *messagingPeer) (*messagingPeer, error) {
	key := string(peer.identityID)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errMessagingServerClosed
	}
	oldPeer := s.peers[key]
	if oldPeer == nil && len(s.peers) >= maxAuthenticatedConnections {
		s.mu.Unlock()
		return nil, errMessagingCapacity
	}
	s.peers[key] = peer
	s.mu.Unlock()
	return oldPeer, nil
}

func (s *MessagingWebSocketServer) unregisterPeer(peer *messagingPeer) {
	key := string(peer.identityID)
	s.mu.Lock()
	if s.peers[key] == peer {
		delete(s.peers, key)
	}
	s.mu.Unlock()
}

func (s *MessagingWebSocketServer) beginSendWorker() bool {
	select {
	case s.sendSlots <- struct{}{}:
	default:
		return false
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.sendSlots
		return false
	}
	s.sendWorkers++
	s.mu.Unlock()
	return true
}

func (s *MessagingWebSocketServer) endSendWorker() {
	s.mu.Lock()
	if s.sendWorkers > 0 {
		s.sendWorkers--
	}
	s.mu.Unlock()
	<-s.sendSlots
}

// Shutdown stops accepting routing work, closes authenticated and in-flight
// handshake sockets, then waits for bounded handler/send work to unwind.
func (s *MessagingWebSocketServer) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
	}
	peers := make([]*messagingPeer, 0, len(s.peers))
	for _, peer := range s.peers {
		peers = append(peers, peer)
	}
	handshakes := make([]*websocket.Conn, 0, len(s.handshakes))
	for conn := range s.handshakes {
		handshakes = append(handshakes, conn)
	}
	s.mu.Unlock()

	for _, peer := range peers {
		peer.stop()
	}
	for _, conn := range handshakes {
		_ = conn.CloseNow()
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		done := s.handlers == 0 && s.sendWorkers == 0 && len(s.pending) == 0
		s.mu.Unlock()
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type messagingPeer struct {
	conn       *websocket.Conn
	identityID []byte
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	stopOnce   sync.Once
	outbound   chan []byte
	sendOps    chan struct{}
	wakeDrain  chan struct{}

	workers         sync.WaitGroup
	mailboxMu       sync.Mutex
	mailboxInflight map[string]struct{}
}

func newMessagingPeer(conn *websocket.Conn, identityID []byte) *messagingPeer {
	ctx, cancel := context.WithCancel(context.Background())
	return &messagingPeer{
		conn:            conn,
		identityID:      bytes.Clone(identityID),
		ctx:             ctx,
		cancel:          cancel,
		done:            make(chan struct{}),
		outbound:        make(chan []byte, messagingOutboundQueueDepth),
		sendOps:         make(chan struct{}, maxConcurrentSendOpsPerPeer),
		wakeDrain:       make(chan struct{}, 1),
		mailboxInflight: make(map[string]struct{}),
	}
}

func (p *messagingPeer) stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		close(p.done)
		_ = p.conn.CloseNow()
	})
}

func (p *messagingPeer) tryEnqueue(frame []byte) bool {
	if len(frame) == 0 || len(frame) > messaging.MaxWireFrameBytes {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
	}
	select {
	case p.outbound <- bytes.Clone(frame):
		return true
	default:
		return false
	}
}

func (p *messagingPeer) signalDrain() {
	select {
	case p.wakeDrain <- struct{}{}:
	default:
	}
}

func (p *messagingPeer) acquireSendOp() bool {
	select {
	case p.sendOps <- struct{}{}:
		return true
	default:
		return false
	}
}

func (p *messagingPeer) releaseSendOp() {
	<-p.sendOps
}

func (p *messagingPeer) mailboxKey(senderIdentityID, messageID []byte) string {
	return string(senderIdentityID) + string(messageID)
}

func (p *messagingPeer) markMailboxInflight(senderIdentityID, messageID []byte) bool {
	key := p.mailboxKey(senderIdentityID, messageID)
	p.mailboxMu.Lock()
	defer p.mailboxMu.Unlock()
	if _, exists := p.mailboxInflight[key]; exists {
		return false
	}
	p.mailboxInflight[key] = struct{}{}
	return true
}

func (p *messagingPeer) clearMailboxInflight(senderIdentityID, messageID []byte) {
	key := p.mailboxKey(senderIdentityID, messageID)
	p.mailboxMu.Lock()
	delete(p.mailboxInflight, key)
	p.mailboxMu.Unlock()
}

func allZeroBytes(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
