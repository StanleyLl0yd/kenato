package messaging

import (
	"bytes"
	"errors"

	"google.golang.org/protobuf/encoding/protowire"
)

var ErrMalformedMessagingWire = errors.New("malformed messaging wire value")

// EncodeEnvelope returns the canonical protobuf encoding persisted by the M4
// mailbox. Callers must validate expiry at their own acceptance time first.
func EncodeEnvelope(envelope Envelope) ([]byte, error) {
	if !validEnvelopeShape(envelope) {
		return nil, ErrMalformedMessagingWire
	}
	var out []byte
	out = protowire.AppendTag(out, 1, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(envelope.ProtocolVersion))
	out = protowire.AppendTag(out, 2, protowire.BytesType)
	out = protowire.AppendBytes(out, envelope.RecipientIdentityID)
	out = protowire.AppendTag(out, 3, protowire.BytesType)
	out = protowire.AppendBytes(out, envelope.MessageID)
	out = protowire.AppendTag(out, 4, protowire.BytesType)
	out = protowire.AppendBytes(out, envelope.Ciphertext)
	out = protowire.AppendTag(out, 5, protowire.VarintType)
	out = protowire.AppendVarint(out, uint64(envelope.ExpiresAtUnixSeconds))
	out = protowire.AppendTag(out, 6, protowire.BytesType)
	out = protowire.AppendBytes(out, envelope.SenderIdentityID)
	if len(out) > MaxEnvelopeBytes {
		return nil, ErrMalformedMessagingWire
	}
	return out, nil
}

// DecodeEnvelope accepts protobuf-compatible field ordering/unknown fields, but
// mailbox reads additionally require re-encoding to exactly match the canonical
// bytes written by EncodeEnvelope.
func DecodeEnvelope(data []byte) (Envelope, error) {
	if len(data) == 0 || len(data) > MaxEnvelopeBytes {
		return Envelope{}, ErrMalformedMessagingWire
	}
	var envelope Envelope
	var seen uint8
	for len(data) > 0 {
		number, wireType, n := protowire.ConsumeTag(data)
		if n < 0 {
			return Envelope{}, ErrMalformedMessagingWire
		}
		data = data[n:]
		switch number {
		case 1:
			if seen&1 != 0 || wireType != protowire.VarintType {
				return Envelope{}, ErrMalformedMessagingWire
			}
			seen |= 1
			value, n := protowire.ConsumeVarint(data)
			if n < 0 || value > uint64(^uint32(0)) {
				return Envelope{}, ErrMalformedMessagingWire
			}
			envelope.ProtocolVersion = uint32(value)
			data = data[n:]
		case 2, 3, 4, 6:
			var mask uint8
			switch number {
			case 2:
				mask = 2
			case 3:
				mask = 4
			case 4:
				mask = 8
			case 6:
				mask = 32
			}
			if seen&mask != 0 || wireType != protowire.BytesType {
				return Envelope{}, ErrMalformedMessagingWire
			}
			seen |= mask
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return Envelope{}, ErrMalformedMessagingWire
			}
			switch number {
			case 2:
				envelope.RecipientIdentityID = bytes.Clone(value)
			case 3:
				envelope.MessageID = bytes.Clone(value)
			case 4:
				envelope.Ciphertext = bytes.Clone(value)
			case 6:
				envelope.SenderIdentityID = bytes.Clone(value)
			}
			data = data[n:]
		case 5:
			if seen&16 != 0 || wireType != protowire.VarintType {
				return Envelope{}, ErrMalformedMessagingWire
			}
			seen |= 16
			value, n := protowire.ConsumeVarint(data)
			if n < 0 || value > uint64(^uint64(0)>>1) {
				return Envelope{}, ErrMalformedMessagingWire
			}
			envelope.ExpiresAtUnixSeconds = int64(value)
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(number, wireType, data)
			if n < 0 {
				return Envelope{}, ErrMalformedMessagingWire
			}
			data = data[n:]
		}
	}
	if !validEnvelopeShape(envelope) {
		return Envelope{}, ErrMalformedMessagingWire
	}
	return envelope, nil
}

func validEnvelopeShape(envelope Envelope) bool {
	return envelope.ProtocolVersion == ProtocolVersion &&
		len(envelope.SenderIdentityID) == IdentityIDBytes &&
		len(envelope.RecipientIdentityID) == IdentityIDBytes &&
		!bytes.Equal(envelope.SenderIdentityID, envelope.RecipientIdentityID) &&
		validMessageID(envelope.MessageID) &&
		len(envelope.Ciphertext) > 0 && len(envelope.Ciphertext) <= MaxCiphertextBytes &&
		envelope.ExpiresAtUnixSeconds > 0
}
