package messaging

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type fakeMailboxStore struct {
	putRecord MailboxRecord
	putCalls  int
	list      []MailboxDelivery
	ackCalls  int
}

func (f *fakeMailboxStore) PutMailbox(_ context.Context, record MailboxRecord) (bool, error) {
	f.putCalls++
	f.putRecord = record
	return true, nil
}

func (f *fakeMailboxStore) ListMailbox(_ context.Context, _ []byte, _ int64, _ int) ([]MailboxDelivery, error) {
	return f.list, nil
}

func (f *fakeMailboxStore) AckMailbox(_ context.Context, _, _, _ []byte) (bool, error) {
	f.ackCalls++
	return true, nil
}

type fakeIdentityDirectory struct {
	exists bool
	err    error
}

func (f fakeIdentityDirectory) IdentityExists(context.Context, []byte) (bool, error) {
	return f.exists, f.err
}

func TestMailboxServiceBindsAuthenticatedSenderAndRecipientExistence(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	store := &fakeMailboxStore{}
	service := newMailboxServiceWithClock(store, fakeIdentityDirectory{exists: true}, func() time.Time { return now })
	sender := testBytes(1, IdentityIDBytes)
	recipient := testBytes(40, IdentityIDBytes)
	envelope := testEnvelope(sender, recipient, testBytes(90, MessageIDBytes), now.Unix()+60)
	encoded := []byte{1, 2, 3}

	if err := service.Store(context.Background(), sender, envelope, encoded); err != nil {
		t.Fatalf("store valid envelope: %v", err)
	}
	if store.putCalls != 1 || store.putRecord.AcceptedAtUnixSeconds != now.Unix() {
		t.Fatal("valid envelope was not passed to persistence exactly once")
	}
	if !bytes.Equal(store.putRecord.EncodedEnvelope, encoded) {
		t.Fatal("encoded envelope changed before persistence")
	}

	wrongSender := bytes.Clone(sender)
	wrongSender[0] ^= 0xff
	if err := service.Store(context.Background(), wrongSender, envelope, encoded); !errors.Is(err, ErrMailboxRejected) {
		t.Fatalf("sender substitution error=%v", err)
	}
	if store.putCalls != 1 {
		t.Fatal("sender substitution reached persistence")
	}
}

func TestMailboxServiceHidesUnknownRecipientBehindGenericRejection(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	store := &fakeMailboxStore{}
	service := newMailboxServiceWithClock(store, fakeIdentityDirectory{exists: false}, func() time.Time { return now })
	sender := testBytes(1, IdentityIDBytes)
	recipient := testBytes(40, IdentityIDBytes)
	envelope := testEnvelope(sender, recipient, testBytes(90, MessageIDBytes), now.Unix()+60)
	if err := service.Store(context.Background(), sender, envelope, []byte{1}); !errors.Is(err, ErrMailboxRejected) {
		t.Fatalf("unknown recipient error=%v", err)
	}
	if store.putCalls != 0 {
		t.Fatal("unknown recipient reached persistence")
	}
}

func TestMailboxServiceRejectsExpiredOversizedAndInvalidPaging(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	store := &fakeMailboxStore{}
	service := newMailboxServiceWithClock(store, fakeIdentityDirectory{exists: true}, func() time.Time { return now })
	sender := testBytes(1, IdentityIDBytes)
	recipient := testBytes(40, IdentityIDBytes)

	expired := testEnvelope(sender, recipient, testBytes(90, MessageIDBytes), now.Unix())
	if err := service.Store(context.Background(), sender, expired, []byte{1}); !errors.Is(err, ErrMailboxRejected) {
		t.Fatalf("expired envelope error=%v", err)
	}
	valid := testEnvelope(sender, recipient, testBytes(91, MessageIDBytes), now.Unix()+60)
	if err := service.Store(context.Background(), sender, valid, make([]byte, MaxEnvelopeBytes+1)); !errors.Is(err, ErrMailboxRejected) {
		t.Fatalf("oversized envelope error=%v", err)
	}
	if _, err := service.Deliveries(context.Background(), recipient, MaxMailboxDeliveryPage+1); !errors.Is(err, ErrMailboxRejected) {
		t.Fatalf("oversized page error=%v", err)
	}
}

func TestMailboxServiceAckRequiresAuthenticatedRecipientContext(t *testing.T) {
	store := &fakeMailboxStore{}
	service := newMailboxServiceWithClock(store, fakeIdentityDirectory{exists: true}, time.Now)
	recipient := testBytes(40, IdentityIDBytes)
	sender := testBytes(1, IdentityIDBytes)
	ack := DeliveryAck{ProtocolVersion: ProtocolVersion, SenderIdentityID: sender, MessageID: testBytes(90, MessageIDBytes)}
	if err := service.Ack(context.Background(), recipient, ack); err != nil {
		t.Fatalf("valid ack: %v", err)
	}
	if store.ackCalls != 1 {
		t.Fatal("valid ack not passed to persistence")
	}
	if err := service.Ack(context.Background(), sender, ack); !errors.Is(err, ErrMailboxRejected) {
		t.Fatalf("self-bound ack error=%v", err)
	}
}

func testEnvelope(sender, recipient, messageID []byte, expiresAt int64) Envelope {
	return Envelope{
		ProtocolVersion:      ProtocolVersion,
		SenderIdentityID:     bytes.Clone(sender),
		RecipientIdentityID:  bytes.Clone(recipient),
		MessageID:            bytes.Clone(messageID),
		Ciphertext:           []byte{1, 2, 3},
		ExpiresAtUnixSeconds: expiresAt,
	}
}

func testBytes(seed byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}
