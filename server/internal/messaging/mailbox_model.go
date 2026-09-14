package messaging

import "errors"

const (
	MaxMailboxBytesPerRecipient int64 = 16 * 1024 * 1024
	MaxMailboxMessagesPerSender       = 1_000
	MaxMailboxBytesPerSender    int64 = 32 * 1024 * 1024
	MaxMailboxMessagesGlobal          = 100_000
	MaxMailboxBytesGlobal       int64 = 256 * 1024 * 1024
	MaxMailboxDeliveryPage            = 50
	MaxMailboxCleanupBatch            = 1_000
)

var (
	ErrMailboxRejected = errors.New("mailbox request rejected")
	ErrMailboxCapacity = errors.New("mailbox capacity reached")
	ErrMailboxCorrupt  = errors.New("mailbox state is invalid")
)

type MailboxRecord struct {
	Envelope              Envelope
	EncodedEnvelope       []byte
	AcceptedAtUnixSeconds int64
}

type MailboxDelivery struct {
	SenderIdentityID     []byte
	RecipientIdentityID  []byte
	MessageID            []byte
	ExpiresAtUnixSeconds int64
	EncodedEnvelope      []byte
}
