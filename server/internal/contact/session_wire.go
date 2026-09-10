package contact

import (
	"bytes"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

func DecodePublishSessionBootstrapRequest(data []byte) (PublishSessionBootstrapRequest, error) {
	if err := validateSessionWireSize(data); err != nil {
		return PublishSessionBootstrapRequest{}, err
	}
	var request PublishSessionBootstrapRequest
	var seen uint8
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		switch number {
		case 1:
			if seen&1 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 1
			parsed, n, err := consumeUint32(wireType, value)
			request.ProtocolVersion = parsed
			return n, err
		case 2:
			if seen&2 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 2
			raw, n, err := consumeBoundedBytes(wireType, value, MaxWireMessageBytes)
			if err != nil {
				return 0, err
			}
			request.Bundle, err = DecodeSessionBootstrapBundle(raw)
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return request, err
}

func EncodePublishSessionBootstrapResponse(generation, revision uint64) []byte {
	var out []byte
	out = appendUint32Field(out, 1, SessionProtocolVersion)
	out = appendUint64Field(out, 2, generation)
	out = appendUint64Field(out, 3, revision)
	return out
}

func DecodeReserveSessionBootstrapRequest(data []byte) (ReserveSessionBootstrapRequest, error) {
	if err := validateSessionWireSize(data); err != nil {
		return ReserveSessionBootstrapRequest{}, err
	}
	var request ReserveSessionBootstrapRequest
	var seen uint8
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		switch number {
		case 1:
			if seen&1 != 0 { return 0, ErrMalformedWire }
			seen |= 1
			parsed, n, err := consumeUint32(wireType, value)
			request.ProtocolVersion = parsed
			return n, err
		case 2:
			if seen&2 != 0 { return 0, ErrMalformedWire }
			seen |= 2
			raw, n, err := consumeBoundedBytes(wireType, value, IdentityIDBytes)
			if err == nil { request.CreatorIdentityID = bytes.Clone(raw) }
			return n, err
		case 3:
			if seen&4 != 0 { return 0, ErrMalformedWire }
			seen |= 4
			raw, n, err := consumeBoundedBytes(wireType, value, IdentityIDBytes)
			if err == nil { request.RedeemerIdentityID = bytes.Clone(raw) }
			return n, err
		case 4:
			if seen&8 != 0 { return 0, ErrMalformedWire }
			seen |= 8
			raw, n, err := consumeBoundedBytes(wireType, value, InviteTokenBytes)
			if err == nil { request.InviteToken = bytes.Clone(raw) }
			return n, err
		case 5:
			if seen&16 != 0 { return 0, ErrMalformedWire }
			seen |= 16
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSignatureBytes)
			if err == nil { request.ReserveSignature = bytes.Clone(raw) }
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return request, err
}

func EncodeReserveSessionBootstrapResponse(bundle SessionBootstrapBundle, key SessionOneTimePreKey) ([]byte, error) {
	encodedBundle, err := EncodeSessionBootstrapBundle(bundle)
	if err != nil { return nil, err }
	encodedKey, err := encodeSessionOneTimePreKey(key)
	if err != nil { return nil, err }
	var out []byte
	out = appendUint32Field(out, 1, SessionProtocolVersion)
	out = appendBytesField(out, 2, encodedBundle)
	out = appendBytesField(out, 3, encodedKey)
	if len(out) > MaxSessionWireMessageBytes { return nil, ErrMalformedWire }
	return out, nil
}

func DecodeSubmitSessionInitRequest(data []byte) (SubmitSessionInitRequest, error) {
	if err := validateSessionWireSize(data); err != nil {
		return SubmitSessionInitRequest{}, err
	}
	var request SubmitSessionInitRequest
	var seen uint16
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		bit := func(mask uint16) error {
			if seen&mask != 0 { return ErrMalformedWire }
			seen |= mask
			return nil
		}
		switch number {
		case 1:
			if err := bit(1); err != nil { return 0, err }
			parsed, n, err := consumeUint32(wireType, value); request.ProtocolVersion = parsed; return n, err
		case 2:
			if err := bit(2); err != nil { return 0, err }
			raw, n, err := consumeBoundedBytes(wireType, value, IdentityIDBytes); if err == nil { request.CreatorIdentityID = bytes.Clone(raw) }; return n, err
		case 3:
			if err := bit(4); err != nil { return 0, err }
			raw, n, err := consumeBoundedBytes(wireType, value, IdentityIDBytes); if err == nil { request.RedeemerIdentityID = bytes.Clone(raw) }; return n, err
		case 4:
			if err := bit(8); err != nil { return 0, err }
			raw, n, err := consumeBoundedBytes(wireType, value, InviteTokenBytes); if err == nil { request.InviteToken = bytes.Clone(raw) }; return n, err
		case 5:
			if err := bit(16); err != nil { return 0, err }
			parsed, n, err := consumeUint64(wireType, value); request.CreatorAccountGeneration = parsed; return n, err
		case 6:
			if err := bit(32); err != nil { return 0, err }
			parsed, n, err := consumeUint64(wireType, value); request.CreatorOneTimePreKeyID = parsed; return n, err
		case 7:
			if err := bit(64); err != nil { return 0, err }
			parsed, n, err := consumeUint64(wireType, value); request.RedeemerAccountGeneration = parsed; return n, err
		case 8:
			if err := bit(128); err != nil { return 0, err }
			parsed, n, err := consumeUint32(wireType, value); request.OlmMessageType = parsed; return n, err
		case 9:
			if err := bit(256); err != nil { return 0, err }
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSessionCiphertextBytes); if err == nil { request.OlmMessage = bytes.Clone(raw) }; return n, err
		case 10:
			if err := bit(512); err != nil { return 0, err }
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSignatureBytes); if err == nil { request.SubmitSignature = bytes.Clone(raw) }; return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return request, err
}

func EncodeSubmitSessionInitResponse() []byte {
	return appendUint32Field(nil, 1, SessionProtocolVersion)
}

func DecodeClaimSessionInitRequest(data []byte) (ClaimSessionInitRequest, error) {
	if err := validateSessionWireSize(data); err != nil {
		return ClaimSessionInitRequest{}, err
	}
	var request ClaimSessionInitRequest
	var seen uint8
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		switch number {
		case 1:
			if seen&1 != 0 { return 0, ErrMalformedWire }; seen |= 1
			parsed, n, err := consumeUint32(wireType, value); request.ProtocolVersion = parsed; return n, err
		case 2:
			if seen&2 != 0 { return 0, ErrMalformedWire }; seen |= 2
			raw, n, err := consumeBoundedBytes(wireType, value, IdentityIDBytes); if err == nil { request.CreatorIdentityID = bytes.Clone(raw) }; return n, err
		case 3:
			if seen&4 != 0 { return 0, ErrMalformedWire }; seen |= 4
			raw, n, err := consumeBoundedBytes(wireType, value, InviteTokenBytes); if err == nil { request.InviteToken = bytes.Clone(raw) }; return n, err
		case 4:
			if seen&8 != 0 { return 0, ErrMalformedWire }; seen |= 8
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSignatureBytes); if err == nil { request.ClaimSignature = bytes.Clone(raw) }; return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return request, err
}

func EncodeClaimSessionInitResponse(result ClaimSessionInitResult) ([]byte, error) {
	identityBundle, err := EncodePublicIdentityBundle(result.RedeemerIdentityBundle)
	if err != nil { return nil, err }
	sessionBundle, err := EncodeSessionBootstrapBundle(result.RedeemerSessionBundle)
	if err != nil { return nil, err }
	oneTimeKey, err := encodeSessionOneTimePreKey(result.CreatorOneTimeKey)
	if err != nil { return nil, err }
	if !validSignature(result.RedemptionSignature) || result.RedeemedAt < 0 || result.OlmMessageType != OlmMessageTypePreKey || len(result.OlmMessage) == 0 || len(result.OlmMessage) > MaxSessionCiphertextBytes {
		return nil, ErrInvalidSessionBootstrap
	}
	var out []byte
	out = appendUint32Field(out, 1, SessionProtocolVersion)
	out = appendBytesField(out, 2, identityBundle)
	out = appendBytesField(out, 3, result.RedemptionSignature)
	out = appendInt64Field(out, 4, result.RedeemedAt)
	out = appendBytesField(out, 5, sessionBundle)
	out = appendBytesField(out, 6, oneTimeKey)
	out = appendUint32Field(out, 7, result.OlmMessageType)
	out = appendBytesField(out, 8, result.OlmMessage)
	if len(out) > MaxSessionWireMessageBytes { return nil, ErrMalformedWire }
	return out, nil
}

func EncodeSessionBootstrapBundle(bundle SessionBootstrapBundle) ([]byte, error) {
	if err := validateSessionBootstrapShape(bundle, true); err != nil { return nil, err }
	var out []byte
	out = appendBytesField(out, 1, bundle.IdentityID)
	out = appendUint64Field(out, 2, bundle.AccountGeneration)
	out = appendUint64Field(out, 3, bundle.PublicationRevision)
	out = appendBytesField(out, 4, bundle.OlmEd25519IdentityKey)
	out = appendBytesField(out, 5, bundle.OlmCurve25519IdentityKey)
	for _, key := range bundle.OneTimePreKeys {
		encoded, err := encodeSessionOneTimePreKey(key)
		if err != nil { return nil, err }
		out = appendBytesField(out, 6, encoded)
	}
	out = appendBytesField(out, 7, bundle.BindingSignature)
	if len(out) == 0 || len(out) > MaxWireMessageBytes { return nil, ErrMalformedWire }
	return out, nil
}

func DecodeSessionBootstrapBundle(data []byte) (SessionBootstrapBundle, error) {
	if len(data) == 0 || len(data) > MaxWireMessageBytes { return SessionBootstrapBundle{}, ErrMalformedWire }
	var bundle SessionBootstrapBundle
	var seen uint8
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		switch number {
		case 1:
			if seen&1 != 0 { return 0, ErrMalformedWire }; seen |= 1
			raw, n, err := consumeBoundedBytes(wireType, value, IdentityIDBytes); if err == nil { bundle.IdentityID = bytes.Clone(raw) }; return n, err
		case 2:
			if seen&2 != 0 { return 0, ErrMalformedWire }; seen |= 2
			parsed, n, err := consumeUint64(wireType, value); bundle.AccountGeneration = parsed; return n, err
		case 3:
			if seen&4 != 0 { return 0, ErrMalformedWire }; seen |= 4
			parsed, n, err := consumeUint64(wireType, value); bundle.PublicationRevision = parsed; return n, err
		case 4:
			if seen&8 != 0 { return 0, ErrMalformedWire }; seen |= 8
			raw, n, err := consumeBoundedBytes(wireType, value, OlmPublicKeyBytes); if err == nil { bundle.OlmEd25519IdentityKey = bytes.Clone(raw) }; return n, err
		case 5:
			if seen&16 != 0 { return 0, ErrMalformedWire }; seen |= 16
			raw, n, err := consumeBoundedBytes(wireType, value, OlmPublicKeyBytes); if err == nil { bundle.OlmCurve25519IdentityKey = bytes.Clone(raw) }; return n, err
		case 6:
			if len(bundle.OneTimePreKeys) >= MaxSessionOneTimePreKeys { return 0, ErrMalformedWire }
			raw, n, err := consumeBoundedBytes(wireType, value, 128)
			if err != nil { return 0, err }
			key, err := decodeSessionOneTimePreKey(raw)
			if err != nil { return 0, err }
			bundle.OneTimePreKeys = append(bundle.OneTimePreKeys, key)
			return n, nil
		case 7:
			if seen&32 != 0 { return 0, ErrMalformedWire }; seen |= 32
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSignatureBytes); if err == nil { bundle.BindingSignature = bytes.Clone(raw) }; return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	if err != nil { return SessionBootstrapBundle{}, err }
	if err := validateSessionBootstrapShape(bundle, true); err != nil { return SessionBootstrapBundle{}, err }
	return bundle, nil
}

func encodeSessionOneTimePreKey(key SessionOneTimePreKey) ([]byte, error) {
	if key.ID == 0 || key.ID > math.MaxInt64 || len(key.PublicKey) != OlmPublicKeyBytes { return nil, ErrInvalidSessionBootstrap }
	var out []byte
	out = appendUint64Field(out, 1, key.ID)
	out = appendBytesField(out, 2, key.PublicKey)
	return out, nil
}

func decodeSessionOneTimePreKey(data []byte) (SessionOneTimePreKey, error) {
	if len(data) == 0 || len(data) > 128 { return SessionOneTimePreKey{}, ErrMalformedWire }
	var key SessionOneTimePreKey
	var seen uint8
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		switch number {
		case 1:
			if seen&1 != 0 { return 0, ErrMalformedWire }; seen |= 1
			parsed, n, err := consumeUint64(wireType, value); key.ID = parsed; return n, err
		case 2:
			if seen&2 != 0 { return 0, ErrMalformedWire }; seen |= 2
			raw, n, err := consumeBoundedBytes(wireType, value, OlmPublicKeyBytes); if err == nil { key.PublicKey = bytes.Clone(raw) }; return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	if err != nil || key.ID == 0 || key.ID > math.MaxInt64 || len(key.PublicKey) != OlmPublicKeyBytes { return SessionOneTimePreKey{}, ErrMalformedWire }
	return key, nil
}

func validateSessionWireSize(data []byte) error {
	if len(data) == 0 || len(data) > MaxSessionWireMessageBytes { return ErrMalformedWire }
	return nil
}
