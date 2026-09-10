package contact

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

const MaxWireMessageBytes = 64 << 10

var ErrMalformedWire = errors.New("malformed contact protocol message")

type PublishIdentityRequest struct {
	ProtocolVersion uint32
	Bundle          PublicIdentityBundle
}

type CreateInviteRequest struct {
	ProtocolVersion uint32
	Invite          InviteDescriptor
}

type RedeemInviteRequest struct {
	ProtocolVersion     uint32
	Invite              InviteDescriptor
	RedeemerBundle      PublicIdentityBundle
	RedemptionSignature []byte
}

type ClaimInviteRequest struct {
	ProtocolVersion   uint32
	CreatorIdentityID []byte
	InviteToken       []byte
	ClaimSignature    []byte
}

func DecodePublishIdentityRequest(data []byte) (PublishIdentityRequest, error) {
	if err := validateWireSize(data); err != nil {
		return PublishIdentityRequest{}, err
	}
	var request PublishIdentityRequest
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
			request.Bundle, err = DecodePublicIdentityBundle(raw)
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return request, err
}

func EncodePublishIdentityResponse(acceptedRevision uint64) []byte {
	var out []byte
	out = appendUint32Field(out, 1, ProtocolVersion)
	out = appendUint64Field(out, 2, acceptedRevision)
	return out
}

func DecodeCreateInviteRequest(data []byte) (CreateInviteRequest, error) {
	if err := validateWireSize(data); err != nil {
		return CreateInviteRequest{}, err
	}
	var request CreateInviteRequest
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
			request.Invite, err = decodeInviteDescriptor(raw)
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return request, err
}

func EncodeCreateInviteResponse(expiresAtUnixSeconds int64) []byte {
	var out []byte
	out = appendUint32Field(out, 1, ProtocolVersion)
	out = appendInt64Field(out, 2, expiresAtUnixSeconds)
	return out
}

func DecodeRedeemInviteRequest(data []byte) (RedeemInviteRequest, error) {
	if err := validateWireSize(data); err != nil {
		return RedeemInviteRequest{}, err
	}
	var request RedeemInviteRequest
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
			request.Invite, err = decodeInviteDescriptor(raw)
			return n, err
		case 3:
			if seen&4 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 4
			raw, n, err := consumeBoundedBytes(wireType, value, MaxWireMessageBytes)
			if err != nil {
				return 0, err
			}
			request.RedeemerBundle, err = DecodePublicIdentityBundle(raw)
			return n, err
		case 4:
			if seen&8 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 8
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSignatureBytes)
			if err == nil {
				request.RedemptionSignature = bytes.Clone(raw)
			}
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return request, err
}

func EncodeRedeemInviteResponse(bundle PublicIdentityBundle, redeemedAtUnixSeconds int64) ([]byte, error) {
	encodedBundle, err := EncodePublicIdentityBundle(bundle)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = appendUint32Field(out, 1, ProtocolVersion)
	out = appendBytesField(out, 2, encodedBundle)
	out = appendInt64Field(out, 3, redeemedAtUnixSeconds)
	return out, nil
}

func DecodeClaimInviteRequest(data []byte) (ClaimInviteRequest, error) {
	if err := validateWireSize(data); err != nil {
		return ClaimInviteRequest{}, err
	}
	var request ClaimInviteRequest
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
			raw, n, err := consumeBoundedBytes(wireType, value, IdentityIDBytes)
			if err == nil {
				request.CreatorIdentityID = bytes.Clone(raw)
			}
			return n, err
		case 3:
			if seen&4 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 4
			raw, n, err := consumeBoundedBytes(wireType, value, InviteTokenBytes)
			if err == nil {
				request.InviteToken = bytes.Clone(raw)
			}
			return n, err
		case 4:
			if seen&8 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 8
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSignatureBytes)
			if err == nil {
				request.ClaimSignature = bytes.Clone(raw)
			}
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return request, err
}

func EncodeClaimInviteResponse(bundle PublicIdentityBundle, redemptionSignature []byte, redeemedAtUnixSeconds int64) ([]byte, error) {
	if !validSignature(redemptionSignature) {
		return nil, ErrInvalidInvite
	}
	encodedBundle, err := EncodePublicIdentityBundle(bundle)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = appendUint32Field(out, 1, ProtocolVersion)
	out = appendBytesField(out, 2, encodedBundle)
	out = appendBytesField(out, 3, redemptionSignature)
	out = appendInt64Field(out, 4, redeemedAtUnixSeconds)
	return out, nil
}

func EncodePublicIdentityBundle(bundle PublicIdentityBundle) ([]byte, error) {
	if err := validateSignedBundleShape(bundle); err != nil {
		return nil, err
	}
	var out []byte
	out = appendBytesField(out, 1, bundle.IdentityID)
	out = appendBytesField(out, 2, bundle.IdentityPublicKey)
	out = appendUint64Field(out, 3, bundle.PublicationRevision)
	out = appendBytesField(out, 4, encodeSignedPreKey(bundle.SignedPreKey))
	for _, preKey := range bundle.OneTimePreKeys {
		out = appendBytesField(out, 5, encodeOneTimePreKey(preKey))
	}
	out = appendBytesField(out, 6, bundle.PublicationSignature)
	if len(out) > MaxWireMessageBytes {
		return nil, ErrMalformedWire
	}
	return out, nil
}

func DecodePublicIdentityBundle(data []byte) (PublicIdentityBundle, error) {
	if err := validateWireSize(data); err != nil {
		return PublicIdentityBundle{}, err
	}
	var bundle PublicIdentityBundle
	var seen uint8
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		switch number {
		case 1:
			if seen&1 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 1
			raw, n, err := consumeBoundedBytes(wireType, value, IdentityIDBytes)
			if err == nil {
				bundle.IdentityID = bytes.Clone(raw)
			}
			return n, err
		case 2:
			if seen&2 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 2
			raw, n, err := consumeBoundedBytes(wireType, value, MaxPublicKeyBytes)
			if err == nil {
				bundle.IdentityPublicKey = bytes.Clone(raw)
			}
			return n, err
		case 3:
			if seen&4 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 4
			parsed, n, err := consumeUint64(wireType, value)
			bundle.PublicationRevision = parsed
			return n, err
		case 4:
			if seen&8 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 8
			raw, n, err := consumeBoundedBytes(wireType, value, MaxWireMessageBytes)
			if err != nil {
				return 0, err
			}
			bundle.SignedPreKey, err = decodeSignedPreKey(raw)
			return n, err
		case 5:
			if len(bundle.OneTimePreKeys) >= MaxOneTimePreKeys {
				return 0, ErrMalformedWire
			}
			raw, n, err := consumeBoundedBytes(wireType, value, MaxWireMessageBytes)
			if err != nil {
				return 0, err
			}
			preKey, err := decodeOneTimePreKey(raw)
			if err != nil {
				return 0, err
			}
			bundle.OneTimePreKeys = append(bundle.OneTimePreKeys, preKey)
			return n, nil
		case 6:
			if seen&16 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 16
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSignatureBytes)
			if err == nil {
				bundle.PublicationSignature = bytes.Clone(raw)
			}
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return bundle, err
}

func decodeInviteDescriptor(data []byte) (InviteDescriptor, error) {
	if err := validateWireSize(data); err != nil {
		return InviteDescriptor{}, err
	}
	var invite InviteDescriptor
	var seen uint8
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		switch number {
		case 1:
			if seen&1 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 1
			raw, n, err := consumeBoundedBytes(wireType, value, IdentityIDBytes)
			if err == nil {
				invite.CreatorIdentityID = bytes.Clone(raw)
			}
			return n, err
		case 2:
			if seen&2 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 2
			raw, n, err := consumeBoundedBytes(wireType, value, InviteTokenBytes)
			if err == nil {
				invite.InviteToken = bytes.Clone(raw)
			}
			return n, err
		case 3:
			if seen&4 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 4
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSignatureBytes)
			if err == nil {
				invite.InviteSignature = bytes.Clone(raw)
			}
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return invite, err
}

func encodeInviteDescriptor(invite InviteDescriptor) ([]byte, error) {
	if err := validateInviteShape(invite); err != nil {
		return nil, err
	}
	var out []byte
	out = appendBytesField(out, 1, invite.CreatorIdentityID)
	out = appendBytesField(out, 2, invite.InviteToken)
	out = appendBytesField(out, 3, invite.InviteSignature)
	return out, nil
}

func decodeSignedPreKey(data []byte) (SignedPreKey, error) {
	var preKey SignedPreKey
	var seen uint8
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		switch number {
		case 1:
			if seen&1 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 1
			parsed, n, err := consumeUint32(wireType, value)
			preKey.ID = parsed
			return n, err
		case 2:
			if seen&2 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 2
			raw, n, err := consumeBoundedBytes(wireType, value, MaxPublicKeyBytes)
			if err == nil {
				preKey.PublicKey = bytes.Clone(raw)
			}
			return n, err
		case 3:
			if seen&4 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 4
			raw, n, err := consumeBoundedBytes(wireType, value, MaxSignatureBytes)
			if err == nil {
				preKey.Signature = bytes.Clone(raw)
			}
			return n, err
		case 4:
			if seen&8 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 8
			parsed, n, err := consumeInt64(wireType, value)
			preKey.CreatedAtUnixSeconds = parsed
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return preKey, err
}

func encodeSignedPreKey(preKey SignedPreKey) []byte {
	var out []byte
	out = appendUint32Field(out, 1, preKey.ID)
	out = appendBytesField(out, 2, preKey.PublicKey)
	out = appendBytesField(out, 3, preKey.Signature)
	out = appendInt64Field(out, 4, preKey.CreatedAtUnixSeconds)
	return out
}

func decodeOneTimePreKey(data []byte) (OneTimePreKey, error) {
	var preKey OneTimePreKey
	var seen uint8
	err := consumeFields(data, func(number protowire.Number, wireType protowire.Type, value []byte) (int, error) {
		switch number {
		case 1:
			if seen&1 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 1
			parsed, n, err := consumeUint32(wireType, value)
			preKey.ID = parsed
			return n, err
		case 2:
			if seen&2 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 2
			raw, n, err := consumeBoundedBytes(wireType, value, MaxPublicKeyBytes)
			if err == nil {
				preKey.PublicKey = bytes.Clone(raw)
			}
			return n, err
		case 3:
			if seen&4 != 0 {
				return 0, ErrMalformedWire
			}
			seen |= 4
			parsed, n, err := consumeInt64(wireType, value)
			preKey.CreatedAtUnixSeconds = parsed
			return n, err
		default:
			return consumeUnknown(number, wireType, value)
		}
	})
	return preKey, err
}

func encodeOneTimePreKey(preKey OneTimePreKey) []byte {
	var out []byte
	out = appendUint32Field(out, 1, preKey.ID)
	out = appendBytesField(out, 2, preKey.PublicKey)
	out = appendInt64Field(out, 3, preKey.CreatedAtUnixSeconds)
	return out
}

func consumeFields(data []byte, handle func(protowire.Number, protowire.Type, []byte) (int, error)) error {
	for len(data) > 0 {
		number, wireType, n := protowire.ConsumeTag(data)
		if n < 0 || number <= 0 {
			return ErrMalformedWire
		}
		data = data[n:]
		consumed, err := handle(number, wireType, data)
		if err != nil || consumed < 0 || consumed > len(data) {
			if err != nil {
				return err
			}
			return ErrMalformedWire
		}
		data = data[consumed:]
	}
	return nil
}

func consumeUnknown(number protowire.Number, wireType protowire.Type, data []byte) (int, error) {
	n := protowire.ConsumeFieldValue(number, wireType, data)
	if n < 0 {
		return 0, ErrMalformedWire
	}
	return n, nil
}

func consumeUint32(wireType protowire.Type, data []byte) (uint32, int, error) {
	value, n, err := consumeUint64(wireType, data)
	if err != nil || value > math.MaxUint32 {
		return 0, n, ErrMalformedWire
	}
	return uint32(value), n, nil
}

func consumeUint64(wireType protowire.Type, data []byte) (uint64, int, error) {
	if wireType != protowire.VarintType {
		return 0, 0, ErrMalformedWire
	}
	value, n := protowire.ConsumeVarint(data)
	if n < 0 {
		return 0, 0, ErrMalformedWire
	}
	return value, n, nil
}

func consumeInt64(wireType protowire.Type, data []byte) (int64, int, error) {
	value, n, err := consumeUint64(wireType, data)
	return int64(value), n, err
}

func consumeBoundedBytes(wireType protowire.Type, data []byte, max int) ([]byte, int, error) {
	if wireType != protowire.BytesType {
		return nil, 0, ErrMalformedWire
	}
	value, n := protowire.ConsumeBytes(data)
	if n < 0 || len(value) > max {
		return nil, 0, ErrMalformedWire
	}
	return value, n, nil
}

func validateWireSize(data []byte) error {
	if len(data) == 0 || len(data) > MaxWireMessageBytes {
		return fmt.Errorf("%w: message size", ErrMalformedWire)
	}
	return nil
}

func appendUint32Field(dst []byte, number protowire.Number, value uint32) []byte {
	dst = protowire.AppendTag(dst, number, protowire.VarintType)
	return protowire.AppendVarint(dst, uint64(value))
}

func appendUint64Field(dst []byte, number protowire.Number, value uint64) []byte {
	dst = protowire.AppendTag(dst, number, protowire.VarintType)
	return protowire.AppendVarint(dst, value)
}

func appendInt64Field(dst []byte, number protowire.Number, value int64) []byte {
	dst = protowire.AppendTag(dst, number, protowire.VarintType)
	return protowire.AppendVarint(dst, uint64(value))
}

func appendBytesField(dst []byte, number protowire.Number, value []byte) []byte {
	dst = protowire.AppendTag(dst, number, protowire.BytesType)
	return protowire.AppendBytes(dst, value)
}
