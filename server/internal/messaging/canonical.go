package messaging

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

var messagingAuthDomain = []byte("KENATO-MESSAGING-AUTH-V1\x00")

// AuthPayload is the exact byte sequence signed with the existing Kenato
// P-256 identity key when authenticating a WSS connection.
func AuthPayload(identityID, challenge []byte, expiresAtUnixSeconds int64) ([]byte, error) {
	if len(identityID) != IdentityIDBytes || !validChallenge(challenge) || expiresAtUnixSeconds <= 0 {
		return nil, ErrInvalidMessaging
	}
	payload := make([]byte, 0, len(messagingAuthDomain)+IdentityIDBytes+AuthChallengeBytes+8)
	payload = append(payload, messagingAuthDomain...)
	payload = append(payload, identityID...)
	payload = append(payload, challenge...)
	payload = binary.BigEndian.AppendUint64(payload, uint64(expiresAtUnixSeconds))
	return payload, nil
}

func ValidateAuthChallenge(challenge AuthChallenge, nowUnixSeconds int64) error {
	if challenge.ProtocolVersion != ProtocolVersion || !validChallenge(challenge.Challenge) || nowUnixSeconds < 0 || challenge.ExpiresAtUnixSeconds <= 0 {
		return ErrInvalidMessaging
	}
	if challenge.ExpiresAtUnixSeconds <= nowUnixSeconds {
		return ErrExpiredMessaging
	}
	if challenge.ExpiresAtUnixSeconds-nowUnixSeconds > MaxAuthChallengeLifetimeSeconds {
		return ErrInvalidMessaging
	}
	return nil
}

func ValidateAuthResponseShape(response AuthResponse) error {
	if response.ProtocolVersion != ProtocolVersion || len(response.IdentityID) != IdentityIDBytes || !validChallenge(response.Challenge) || response.ExpiresAtUnixSeconds <= 0 {
		return ErrInvalidMessaging
	}
	if len(response.Signature) == 0 || len(response.Signature) > MaxAuthSignatureBytes {
		return ErrInvalidMessaging
	}
	return nil
}

func ValidateAuthResponseForChallenge(response AuthResponse, challenge AuthChallenge, nowUnixSeconds int64) error {
	if err := ValidateAuthChallenge(challenge, nowUnixSeconds); err != nil {
		return err
	}
	if err := ValidateAuthResponseShape(response); err != nil {
		return err
	}
	if !bytes.Equal(response.Challenge, challenge.Challenge) || response.ExpiresAtUnixSeconds != challenge.ExpiresAtUnixSeconds {
		return ErrInvalidMessaging
	}
	return nil
}

func ValidateEnvelopeAt(envelope Envelope, nowUnixSeconds int64) error {
	if envelope.ProtocolVersion != ProtocolVersion || len(envelope.SenderIdentityID) != IdentityIDBytes || len(envelope.RecipientIdentityID) != IdentityIDBytes || bytes.Equal(envelope.SenderIdentityID, envelope.RecipientIdentityID) {
		return ErrInvalidMessaging
	}
	if !validMessageID(envelope.MessageID) || len(envelope.Ciphertext) == 0 || len(envelope.Ciphertext) > MaxCiphertextBytes || nowUnixSeconds < 0 {
		return ErrInvalidMessaging
	}
	if envelope.ExpiresAtUnixSeconds <= nowUnixSeconds {
		return ErrExpiredMessaging
	}
	if envelope.ExpiresAtUnixSeconds-nowUnixSeconds > MaxMessageTTLSeconds {
		return ErrInvalidMessaging
	}
	return nil
}

func ValidatePlaintext(plaintext Plaintext) error {
	if plaintext.ProtocolVersion != ProtocolVersion || len(plaintext.SenderIdentityID) != IdentityIDBytes || len(plaintext.RecipientIdentityID) != IdentityIDBytes || bytes.Equal(plaintext.SenderIdentityID, plaintext.RecipientIdentityID) {
		return ErrInvalidMessaging
	}
	if !validMessageID(plaintext.MessageID) || plaintext.SentAtUnixSeconds <= 0 || plaintext.ExpiresAtUnixSeconds <= plaintext.SentAtUnixSeconds {
		return ErrInvalidMessaging
	}
	if plaintext.ExpiresAtUnixSeconds-plaintext.SentAtUnixSeconds > MaxMessageTTLSeconds {
		return ErrInvalidMessaging
	}
	if len(plaintext.Text) == 0 || len(plaintext.Text) > MaxTextBytes || !utf8.ValidString(plaintext.Text) {
		return ErrInvalidMessaging
	}
	return nil
}

// ValidateDeliveryContext binds server-visible routing metadata to the
// authenticated plaintext recovered from the M3 session. A correct recipient
// must reject any relay-side rewrite of sender, recipient, id or expiry.
func ValidateDeliveryContext(envelope Envelope, plaintext Plaintext, nowUnixSeconds int64) error {
	if err := ValidateEnvelopeAt(envelope, nowUnixSeconds); err != nil {
		return err
	}
	if err := ValidatePlaintext(plaintext); err != nil {
		return err
	}
	if !bytes.Equal(envelope.SenderIdentityID, plaintext.SenderIdentityID) ||
		!bytes.Equal(envelope.RecipientIdentityID, plaintext.RecipientIdentityID) ||
		!bytes.Equal(envelope.MessageID, plaintext.MessageID) ||
		envelope.ExpiresAtUnixSeconds != plaintext.ExpiresAtUnixSeconds {
		return ErrInvalidMessaging
	}
	return nil
}

func validChallenge(value []byte) bool {
	return len(value) == AuthChallengeBytes && !allZero(value)
}

func validMessageID(value []byte) bool {
	return len(value) == MessageIDBytes && !allZero(value)
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
