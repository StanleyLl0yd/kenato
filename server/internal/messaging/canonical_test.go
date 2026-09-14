package messaging

import (
	"bytes"
	"errors"
	"testing"
)

func TestAuthPayloadMatchesM4Vector(t *testing.T) {
	identity := sequence(0x00, IdentityIDBytes)
	challenge := sequence(0x20, AuthChallengeBytes)
	got, err := AuthPayload(identity, challenge, 1700000030)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "4b454e41544f2d4d4553534147494e472d415554482d563100"+
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"+
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"+
		"000000006553f11e")
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical payload mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestAuthChallengeAndResponseAreBoundExactly(t *testing.T) {
	challenge := AuthChallenge{ProtocolVersion: 1, Challenge: sequence(1, AuthChallengeBytes), ExpiresAtUnixSeconds: 1030}
	response := AuthResponse{ProtocolVersion: 1, IdentityID: sequence(0x40, IdentityIDBytes), Challenge: bytes.Clone(challenge.Challenge), ExpiresAtUnixSeconds: 1030, Signature: []byte{1}}
	if err := ValidateAuthResponseForChallenge(response, challenge, 1000); err != nil {
		t.Fatalf("valid challenge/response rejected: %v", err)
	}
	response.Challenge[0] ^= 0xff
	if !errors.Is(ValidateAuthResponseForChallenge(response, challenge, 1000), ErrInvalidMessaging) {
		t.Fatal("mismatched challenge was accepted")
	}
	if !errors.Is(ValidateAuthChallenge(challenge, 1030), ErrExpiredMessaging) {
		t.Fatal("challenge remained valid at exact expiry")
	}
}

func TestDeliveryContextRejectsRelayMetadataRewrite(t *testing.T) {
	now := int64(1_700_000_000)
	sender := sequence(0x00, IdentityIDBytes)
	recipient := sequence(0x20, IdentityIDBytes)
	messageID := sequence(0x40, MessageIDBytes)
	expires := now + 3600
	envelope := Envelope{ProtocolVersion: 1, SenderIdentityID: sender, RecipientIdentityID: recipient, MessageID: messageID, Ciphertext: []byte{1, 2, 3}, ExpiresAtUnixSeconds: expires}
	plaintext := Plaintext{ProtocolVersion: 1, SenderIdentityID: bytes.Clone(sender), RecipientIdentityID: bytes.Clone(recipient), MessageID: bytes.Clone(messageID), SentAtUnixSeconds: now, ExpiresAtUnixSeconds: expires, Text: "hello"}
	if err := ValidateDeliveryContext(envelope, plaintext, now); err != nil {
		t.Fatalf("valid context rejected: %v", err)
	}
	plaintext.MessageID[0] ^= 0xff
	if !errors.Is(ValidateDeliveryContext(envelope, plaintext, now), ErrInvalidMessaging) {
		t.Fatal("rewritten outer message id was not detected")
	}
}

func TestEnvelopeAndPlaintextBounds(t *testing.T) {
	now := int64(10_000)
	envelope := Envelope{ProtocolVersion: 1, SenderIdentityID: sequence(0x00, IdentityIDBytes), RecipientIdentityID: sequence(0x20, IdentityIDBytes), MessageID: sequence(0x40, MessageIDBytes), Ciphertext: []byte{1}, ExpiresAtUnixSeconds: now + MaxMessageTTLSeconds}
	if err := ValidateEnvelopeAt(envelope, now); err != nil {
		t.Fatalf("exact max TTL rejected: %v", err)
	}
	envelope.ExpiresAtUnixSeconds++
	if !errors.Is(ValidateEnvelopeAt(envelope, now), ErrInvalidMessaging) {
		t.Fatal("overlong TTL accepted")
	}
	envelope.ExpiresAtUnixSeconds = now
	if !errors.Is(ValidateEnvelopeAt(envelope, now), ErrExpiredMessaging) {
		t.Fatal("exact expiry boundary accepted")
	}

	plaintext := Plaintext{ProtocolVersion: 1, SenderIdentityID: sequence(0x00, IdentityIDBytes), RecipientIdentityID: sequence(0x20, IdentityIDBytes), MessageID: sequence(0x40, MessageIDBytes), SentAtUnixSeconds: now, ExpiresAtUnixSeconds: now + 1, Text: "x"}
	if err := ValidatePlaintext(plaintext); err != nil {
		t.Fatalf("valid plaintext rejected: %v", err)
	}
	plaintext.Text = string(bytes.Repeat([]byte{'x'}, MaxTextBytes+1))
	if !errors.Is(ValidatePlaintext(plaintext), ErrInvalidMessaging) {
		t.Fatal("oversized text accepted")
	}
}

func sequence(start byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	if len(value)%2 != 0 {
		t.Fatal("odd hex length")
	}
	out := make([]byte, len(value)/2)
	for i := range out {
		var high, low byte
		for j, target := range []*byte{&high, &low} {
			c := value[2*i+j]
			switch {
			case c >= '0' && c <= '9':
				*target = c - '0'
			case c >= 'a' && c <= 'f':
				*target = c - 'a' + 10
			default:
				t.Fatalf("invalid hex byte %q", c)
			}
		}
		out[i] = high<<4 | low
	}
	return out
}
