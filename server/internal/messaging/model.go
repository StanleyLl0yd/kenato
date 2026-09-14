package messaging

import "errors"

const (
	ProtocolVersion                 uint32 = 1
	IdentityIDBytes                        = 32
	MessageIDBytes                         = 16
	AuthChallengeBytes                     = 32
	MaxAuthSignatureBytes                  = 256
	MaxTextBytes                           = 16 * 1024
	MaxCiphertextBytes                     = 64 * 1024
	MaxEnvelopeBytes                       = 96 * 1024
	MaxWireFrameBytes                      = 100 * 1024
	MaxMailboxMessagesPerRecipient         = 500
	MaxMessageTTLSeconds            int64  = 72 * 60 * 60
	MaxAuthChallengeLifetimeSeconds int64  = 30
)

var (
	ErrInvalidMessaging = errors.New("invalid messaging protocol value")
	ErrExpiredMessaging = errors.New("messaging value expired")
)

type MessagingErrorCode uint32

const (
	MessagingErrorMalformed MessagingErrorCode = iota + 1
	MessagingErrorAuthenticationFailed
	MessagingErrorSendRejected
	MessagingErrorRetryLater
)

type Envelope struct {
	ProtocolVersion      uint32
	RecipientIdentityID  []byte
	MessageID            []byte
	Ciphertext           []byte
	ExpiresAtUnixSeconds int64
	SenderIdentityID     []byte
}

type Plaintext struct {
	ProtocolVersion      uint32
	SenderIdentityID     []byte
	RecipientIdentityID  []byte
	MessageID            []byte
	SentAtUnixSeconds    int64
	ExpiresAtUnixSeconds int64
	Text                 string
}

type AuthChallenge struct {
	ProtocolVersion      uint32
	Challenge            []byte
	ExpiresAtUnixSeconds int64
}

type AuthResponse struct {
	ProtocolVersion      uint32
	IdentityID           []byte
	Challenge            []byte
	ExpiresAtUnixSeconds int64
	Signature            []byte
}

type DeliveryAck struct {
	ProtocolVersion  uint32
	SenderIdentityID []byte
	MessageID        []byte
}

type SendAccepted struct {
	ProtocolVersion     uint32
	RecipientIdentityID []byte
	MessageID           []byte
}

type MessagingError struct {
	ProtocolVersion uint32
	Code            MessagingErrorCode
	MessageID       []byte
}

type ClientFrame struct {
	ProtocolVersion uint32
	AuthResponse    *AuthResponse
	Send            *Envelope
	Ack             *DeliveryAck
}

type ServerFrame struct {
	ProtocolVersion uint32
	AuthChallenge   *AuthChallenge
	Authenticated   bool
	Delivery        *Envelope
	SendAccepted    *SendAccepted
	Error           *MessagingError
}
