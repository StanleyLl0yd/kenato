package messaging

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestEnvelopeCanonicalWireRoundTrip(t *testing.T) {
	envelope := Envelope{
		ProtocolVersion:      ProtocolVersion,
		SenderIdentityID:     testBytes(1, IdentityIDBytes),
		RecipientIdentityID:  testBytes(40, IdentityIDBytes),
		MessageID:            testBytes(90, MessageIDBytes),
		Ciphertext:           []byte{1, 2, 3, 4},
		ExpiresAtUnixSeconds: 2_000_000_100,
	}
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ProtocolVersion != envelope.ProtocolVersion ||
		!bytes.Equal(decoded.SenderIdentityID, envelope.SenderIdentityID) ||
		!bytes.Equal(decoded.RecipientIdentityID, envelope.RecipientIdentityID) ||
		!bytes.Equal(decoded.MessageID, envelope.MessageID) ||
		!bytes.Equal(decoded.Ciphertext, envelope.Ciphertext) ||
		decoded.ExpiresAtUnixSeconds != envelope.ExpiresAtUnixSeconds {
		t.Fatal("envelope wire round-trip changed fields")
	}
	reencoded, err := EncodeEnvelope(decoded)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		t.Fatal("canonical envelope encoding is not stable")
	}
}

func TestDecodeEnvelopeRejectsDuplicateSingularField(t *testing.T) {
	envelope := testEnvelope(testBytes(1, IdentityIDBytes), testBytes(40, IdentityIDBytes), testBytes(90, MessageIDBytes), 2_000_000_100)
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	encoded = protowire.AppendTag(encoded, 1, protowire.VarintType)
	encoded = protowire.AppendVarint(encoded, uint64(ProtocolVersion))
	if _, err := DecodeEnvelope(encoded); !errors.Is(err, ErrMalformedMessagingWire) {
		t.Fatalf("duplicate singular field error=%v", err)
	}
}

func TestDecodeEnvelopeUnknownFieldCannotBecomeCanonicalMailboxBytes(t *testing.T) {
	envelope := testEnvelope(testBytes(1, IdentityIDBytes), testBytes(40, IdentityIDBytes), testBytes(90, MessageIDBytes), 2_000_000_100)
	canonical, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	withUnknown := append([]byte(nil), canonical...)
	withUnknown = protowire.AppendTag(withUnknown, 99, protowire.VarintType)
	withUnknown = protowire.AppendVarint(withUnknown, 1)
	decoded, err := DecodeEnvelope(withUnknown)
	if err != nil {
		t.Fatalf("protobuf-compatible unknown field rejected: %v", err)
	}
	reencoded, err := EncodeEnvelope(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reencoded, withUnknown) || !bytes.Equal(reencoded, canonical) {
		t.Fatal("unknown field survived canonical mailbox encoding")
	}
}

func TestEnvelopeWireRejectsOversizedCiphertext(t *testing.T) {
	envelope := testEnvelope(testBytes(1, IdentityIDBytes), testBytes(40, IdentityIDBytes), testBytes(90, MessageIDBytes), 2_000_000_100)
	envelope.Ciphertext = make([]byte, MaxCiphertextBytes+1)
	if _, err := EncodeEnvelope(envelope); !errors.Is(err, ErrMalformedMessagingWire) {
		t.Fatalf("oversized ciphertext encode error=%v", err)
	}
}
