package httpapi

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/StanleyLl0yd/kenato/server/internal/messaging"
)

func (s *MessagingWebSocketServer) handleSend(peer *messagingPeer, envelope messaging.Envelope) {
	now := s.clock().UTC().Unix()
	if !bytes.Equal(peer.identityID, envelope.SenderIdentityID) || messaging.ValidateEnvelopeAt(envelope, now) != nil {
		if !s.enqueueError(peer, messaging.MessagingErrorSendRejected, envelope.MessageID) {
			peer.stop()
		}
		return
	}
	if !peer.acquireSendOp() {
		if !s.enqueueError(peer, messaging.MessagingErrorRetryLater, envelope.MessageID) {
			peer.stop()
		}
		return
	}
	if !s.beginSendWorker() {
		peer.releaseSendOp()
		if !s.enqueueError(peer, messaging.MessagingErrorRetryLater, envelope.MessageID) {
			peer.stop()
		}
		return
	}

	go func() {
		defer peer.releaseSendOp()
		defer s.endSendWorker()

		err := s.routeEnvelope(envelope)
		if err != nil {
			// Storage/directory/server failures are potentially transient. Only exact
			// authenticated message-id conflict or an explicit mailbox rejection is
			// permanent enough to tell the client to fail this staged send closed.
			code := messaging.MessagingErrorRetryLater
			if errors.Is(err, errMessagingConflict) || errors.Is(err, messaging.ErrMailboxRejected) {
				code = messaging.MessagingErrorSendRejected
			}
			if !s.enqueueError(peer, code, envelope.MessageID) {
				peer.stop()
			}
			return
		}
		frame, err := messaging.EncodeServerFrame(messaging.ServerFrame{
			ProtocolVersion: messaging.ProtocolVersion,
			SendAccepted: &messaging.SendAccepted{
				ProtocolVersion:     messaging.ProtocolVersion,
				RecipientIdentityID: bytes.Clone(envelope.RecipientIdentityID),
				MessageID:           bytes.Clone(envelope.MessageID),
			},
		})
		if err != nil || !peer.tryEnqueue(frame) {
			peer.stop()
		}
	}()
}

func (s *MessagingWebSocketServer) handleAck(peer *messagingPeer, ack messaging.DeliveryAck) {
	if ack.ProtocolVersion != messaging.ProtocolVersion || len(ack.SenderIdentityID) != messaging.IdentityIDBytes || len(ack.MessageID) != messaging.MessageIDBytes {
		if !s.enqueueError(peer, messaging.MessagingErrorMalformed, ack.MessageID) {
			peer.stop()
		}
		return
	}

	// Direct ACK resolution happens before durable deletion so a healthy online
	// delivery is not held hostage by a slow mailbox operation. A fallback that
	// races this ACK performs a second idempotent delete after its store commit.
	s.ackDirect(peer.identityID, ack.SenderIdentityID, ack.MessageID)

	ctx, cancel := context.WithTimeout(peer.ctx, messagingMailboxOperationTimeout)
	err := s.mailbox.Ack(ctx, peer.identityID, ack)
	cancel()
	if err != nil {
		code := messaging.MessagingErrorRetryLater
		if errors.Is(err, messaging.ErrMailboxRejected) {
			code = messaging.MessagingErrorMalformed
		}
		if !s.enqueueError(peer, code, ack.MessageID) {
			peer.stop()
		}
		return
	}
	peer.clearMailboxInflight(ack.SenderIdentityID, ack.MessageID)
	peer.signalDrain()
}

func (s *MessagingWebSocketServer) routeEnvelope(envelope messaging.Envelope) error {
	encodedEnvelope, err := messaging.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}

	pending, recipientPeer, joined, err := s.beginDirect(envelope, encodedEnvelope)
	if err != nil {
		return err
	}
	if joined {
		return pending.wait()
	}
	if pending == nil || recipientPeer == nil {
		return s.storeMailbox(envelope)
	}

	deliveryFrame, err := messaging.EncodeServerFrame(messaging.ServerFrame{
		ProtocolVersion: messaging.ProtocolVersion,
		Delivery:        &envelope,
	})
	if err != nil {
		s.finishPending(pending, err)
		return err
	}
	if !recipientPeer.tryEnqueue(deliveryFrame) {
		return s.fallbackPending(pending, envelope)
	}

	timer := time.NewTimer(messagingDirectAckTimeout)
	defer timer.Stop()
	select {
	case <-pending.ackCh:
		s.finishPending(pending, nil)
		return nil
	case <-recipientPeer.done:
		return s.fallbackPending(pending, envelope)
	case <-timer.C:
		return s.fallbackPending(pending, envelope)
	}
}

func (s *MessagingWebSocketServer) beginDirect(envelope messaging.Envelope, encodedEnvelope []byte) (*directPending, *messagingPeer, bool, error) {
	key := directPendingKey(envelope.SenderIdentityID, envelope.MessageID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, false, errMessagingServerClosed
	}
	if existing := s.pending[key]; existing != nil {
		if !bytes.Equal(existing.encodedEnvelope, encodedEnvelope) {
			return nil, nil, false, errMessagingConflict
		}
		return existing, existing.recipientPeer, true, nil
	}
	recipientPeer := s.peers[string(envelope.RecipientIdentityID)]
	if recipientPeer == nil || len(s.pending) >= maxPendingDirectDeliveries {
		return nil, nil, false, nil
	}
	pending := &directPending{
		key:             key,
		recipientID:     bytes.Clone(envelope.RecipientIdentityID),
		senderID:        bytes.Clone(envelope.SenderIdentityID),
		messageID:       bytes.Clone(envelope.MessageID),
		encodedEnvelope: bytes.Clone(encodedEnvelope),
		recipientPeer:   recipientPeer,
		ackCh:           make(chan struct{}),
		doneCh:          make(chan struct{}),
	}
	s.pending[key] = pending
	return pending, recipientPeer, false, nil
}

func (s *MessagingWebSocketServer) ackDirect(recipientIdentityID, senderIdentityID, messageID []byte) {
	key := directPendingKey(senderIdentityID, messageID)
	s.mu.Lock()
	pending := s.pending[key]
	s.mu.Unlock()
	if pending == nil || !bytes.Equal(pending.recipientID, recipientIdentityID) {
		return
	}
	pending.markAcked()
}

func (s *MessagingWebSocketServer) fallbackPending(pending *directPending, envelope messaging.Envelope) error {
	if pending.isAcked() {
		s.finishPending(pending, nil)
		return nil
	}

	storeErr := s.storeMailbox(envelope)
	if pending.isAcked() {
		// The ACK may have won the race just before or during durable fallback.
		// Repeat the authenticated delete after Store so a newly committed row
		// cannot be stranded by an ACK that arrived a few microseconds earlier.
		ctx, cancel := context.WithTimeout(context.Background(), messagingMailboxOperationTimeout)
		_ = s.mailbox.Ack(ctx, pending.recipientID, messaging.DeliveryAck{
			ProtocolVersion:  messaging.ProtocolVersion,
			SenderIdentityID: bytes.Clone(pending.senderID),
			MessageID:        bytes.Clone(pending.messageID),
		})
		cancel()
		s.finishPending(pending, nil)
		return nil
	}
	if storeErr != nil {
		s.finishPending(pending, storeErr)
		return storeErr
	}
	s.finishPending(pending, nil)
	return nil
}

func (s *MessagingWebSocketServer) finishPending(pending *directPending, result error) {
	pending.finish(result)
	s.mu.Lock()
	if s.pending[pending.key] == pending {
		delete(s.pending, pending.key)
	}
	s.mu.Unlock()
}

func (s *MessagingWebSocketServer) storeMailbox(envelope messaging.Envelope) error {
	ctx, cancel := context.WithTimeout(context.Background(), messagingMailboxOperationTimeout)
	err := s.mailbox.Store(ctx, envelope.SenderIdentityID, envelope)
	cancel()
	if err != nil {
		return err
	}

	// The recipient may have authenticated or replaced its connection while the
	// durable fallback was being committed. Wake whichever peer currently owns
	// that identity so a row committed after its initial drain is not stranded
	// until an unrelated write or reconnect.
	s.mu.Lock()
	recipientPeer := s.peers[string(envelope.RecipientIdentityID)]
	s.mu.Unlock()
	if recipientPeer != nil {
		recipientPeer.signalDrain()
	}
	return nil
}

func (s *MessagingWebSocketServer) runMailboxDrain(peer *messagingPeer) {
	for {
		select {
		case <-peer.done:
			return
		case <-peer.wakeDrain:
			if err := s.drainMailboxOnce(peer); err != nil {
				// Retained rows remain durable. Do not turn an internal storage
				// failure into a presence/state oracle or an error-frame retry loop.
				continue
			}
		}
	}
}

func (s *MessagingWebSocketServer) drainMailboxOnce(peer *messagingPeer) error {
	ctx, cancel := context.WithTimeout(peer.ctx, messagingMailboxOperationTimeout)
	deliveries, err := s.mailbox.Deliveries(ctx, peer.identityID, messaging.MaxMailboxDeliveryPage)
	cancel()
	if err != nil {
		return err
	}
	for _, delivery := range deliveries {
		select {
		case <-peer.done:
			return nil
		default:
		}
		if !peer.markMailboxInflight(delivery.SenderIdentityID, delivery.MessageID) {
			continue
		}
		envelope, err := messaging.DecodeEnvelope(delivery.EncodedEnvelope)
		if err != nil || !bytes.Equal(envelope.RecipientIdentityID, peer.identityID) {
			peer.clearMailboxInflight(delivery.SenderIdentityID, delivery.MessageID)
			if err != nil {
				return err
			}
			return messaging.ErrMailboxCorrupt
		}
		frame, err := messaging.EncodeServerFrame(messaging.ServerFrame{
			ProtocolVersion: messaging.ProtocolVersion,
			Delivery:        &envelope,
		})
		if err != nil || !peer.tryEnqueue(frame) {
			peer.clearMailboxInflight(delivery.SenderIdentityID, delivery.MessageID)
			if err != nil {
				return err
			}
			return nil
		}
	}
	return nil
}

type directPending struct {
	key             string
	recipientID     []byte
	senderID        []byte
	messageID       []byte
	encodedEnvelope []byte
	recipientPeer   *messagingPeer
	ackCh           chan struct{}
	doneCh          chan struct{}

	mu       sync.Mutex
	acked    bool
	finished bool
	result   error
}

func (p *directPending) markAcked() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished || p.acked {
		return
	}
	p.acked = true
	close(p.ackCh)
}

func (p *directPending) isAcked() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.acked
}

func (p *directPending) finish(result error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.finished = true
	p.result = result
	close(p.doneCh)
}

func (p *directPending) wait() error {
	<-p.doneCh
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.result
}

func directPendingKey(senderIdentityID, messageID []byte) string {
	return string(senderIdentityID) + string(messageID)
}
