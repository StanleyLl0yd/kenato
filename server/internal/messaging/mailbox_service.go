package messaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"
)

type MailboxPersistence interface {
	PutMailbox(context.Context, MailboxRecord) (bool, error)
	ListMailbox(context.Context, []byte, int64, int) ([]MailboxDelivery, error)
	AckMailbox(context.Context, []byte, []byte, []byte) (bool, error)
}

type IdentityDirectory interface {
	IdentityExists(context.Context, []byte) (bool, error)
}

type MailboxService struct {
	store      MailboxPersistence
	identities IdentityDirectory
	clock      func() time.Time
}

func NewMailboxService(store MailboxPersistence, identities IdentityDirectory) *MailboxService {
	return &MailboxService{store: store, identities: identities, clock: time.Now}
}

func newMailboxServiceWithClock(store MailboxPersistence, identities IdentityDirectory, clock func() time.Time) *MailboxService {
	return &MailboxService{store: store, identities: identities, clock: clock}
}

// Store accepts only structured, already-parsed envelope fields. The mailbox
// owns the canonical protobuf encoding it persists, so routing metadata and the
// exact bytes later redelivered cannot diverge through a caller-supplied raw
// encoding.
func (s *MailboxService) Store(ctx context.Context, authenticatedSender []byte, envelope Envelope) error {
	if s == nil || s.store == nil || s.identities == nil || s.clock == nil {
		return errors.New("mailbox service unavailable")
	}
	if len(authenticatedSender) != IdentityIDBytes || !bytes.Equal(authenticatedSender, envelope.SenderIdentityID) {
		return ErrMailboxRejected
	}
	now := s.clock().UTC().Unix()
	if now < 0 {
		return ErrMailboxRejected
	}
	if err := ValidateEnvelopeAt(envelope, now); err != nil {
		return ErrMailboxRejected
	}
	encodedEnvelope, err := EncodeEnvelope(envelope)
	if err != nil || len(encodedEnvelope) > MaxEnvelopeBytes {
		return ErrMailboxRejected
	}
	exists, err := s.identities.IdentityExists(ctx, envelope.RecipientIdentityID)
	if err != nil {
		return fmt.Errorf("resolve mailbox recipient: %w", err)
	}
	if !exists {
		return ErrMailboxRejected
	}
	_, err = s.store.PutMailbox(ctx, MailboxRecord{
		Envelope: Envelope{
			ProtocolVersion:      envelope.ProtocolVersion,
			SenderIdentityID:     bytes.Clone(envelope.SenderIdentityID),
			RecipientIdentityID:  bytes.Clone(envelope.RecipientIdentityID),
			MessageID:            bytes.Clone(envelope.MessageID),
			Ciphertext:           bytes.Clone(envelope.Ciphertext),
			ExpiresAtUnixSeconds: envelope.ExpiresAtUnixSeconds,
		},
		EncodedEnvelope:       encodedEnvelope,
		AcceptedAtUnixSeconds: now,
	})
	return err
}

func (s *MailboxService) Deliveries(ctx context.Context, authenticatedRecipient []byte, limit int) ([]MailboxDelivery, error) {
	if s == nil || s.store == nil || s.clock == nil {
		return nil, errors.New("mailbox service unavailable")
	}
	if len(authenticatedRecipient) != IdentityIDBytes || limit <= 0 || limit > MaxMailboxDeliveryPage {
		return nil, ErrMailboxRejected
	}
	now := s.clock().UTC().Unix()
	if now < 0 {
		return nil, ErrMailboxRejected
	}
	return s.store.ListMailbox(ctx, authenticatedRecipient, now, limit)
}

func (s *MailboxService) Ack(ctx context.Context, authenticatedRecipient []byte, ack DeliveryAck) error {
	if s == nil || s.store == nil {
		return errors.New("mailbox service unavailable")
	}
	if ack.ProtocolVersion != ProtocolVersion || len(authenticatedRecipient) != IdentityIDBytes || len(ack.SenderIdentityID) != IdentityIDBytes || bytes.Equal(authenticatedRecipient, ack.SenderIdentityID) || !validMessageID(ack.MessageID) {
		return ErrMailboxRejected
	}
	_, err := s.store.AckMailbox(ctx, authenticatedRecipient, ack.SenderIdentityID, ack.MessageID)
	return err
}
