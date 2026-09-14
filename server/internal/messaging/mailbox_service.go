package messaging

import (
	"bytes"
	"context"
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

func (s *MailboxService) Store(
	ctx context.Context,
	authenticatedSender []byte,
	envelope Envelope,
	encodedEnvelope []byte,
) error {
	if s == nil || s.store == nil || s.identities == nil || s.clock == nil {
		return errorsUnavailableMailbox()
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
	if len(encodedEnvelope) == 0 || len(encodedEnvelope) > MaxEnvelopeBytes {
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
		EncodedEnvelope:       bytes.Clone(encodedEnvelope),
		AcceptedAtUnixSeconds: now,
	})
	return err
}

func (s *MailboxService) Deliveries(ctx context.Context, authenticatedRecipient []byte, limit int) ([]MailboxDelivery, error) {
	if s == nil || s.store == nil || s.clock == nil {
		return nil, errorsUnavailableMailbox()
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
		return errorsUnavailableMailbox()
	}
	if ack.ProtocolVersion != ProtocolVersion || len(authenticatedRecipient) != IdentityIDBytes || len(ack.SenderIdentityID) != IdentityIDBytes || bytes.Equal(authenticatedRecipient, ack.SenderIdentityID) || !validMessageID(ack.MessageID) {
		return ErrMailboxRejected
	}
	_, err := s.store.AckMailbox(ctx, authenticatedRecipient, ack.SenderIdentityID, ack.MessageID)
	return err
}

func errorsUnavailableMailbox() error {
	return fmt.Errorf("mailbox service unavailable")
}
