package messaging

import (
	"bytes"
	"errors"

	"google.golang.org/protobuf/encoding/protowire"
)

var ErrMalformedMessagingFrame = errors.New("malformed messaging frame")

func EncodeClientFrame(frame ClientFrame) ([]byte, error) {
	if frame.ProtocolVersion != ProtocolVersion || clientPayloadCount(frame) != 1 {
		return nil, ErrMalformedMessagingFrame
	}
	var number protowire.Number
	var nested []byte
	var err error
	switch {
	case frame.AuthResponse != nil:
		number = 2
		nested, err = encodeAuthResponse(*frame.AuthResponse)
	case frame.Send != nil:
		number = 3
		nested, err = EncodeEnvelope(*frame.Send)
	case frame.Ack != nil:
		number = 4
		nested, err = encodeDeliveryAck(*frame.Ack)
	}
	if err != nil {
		return nil, ErrMalformedMessagingFrame
	}
	out := appendVersion(nil)
	out = appendBytesField(out, number, nested)
	if len(out) > MaxWireFrameBytes {
		return nil, ErrMalformedMessagingFrame
	}
	return out, nil
}

func DecodeClientFrame(data []byte) (ClientFrame, error) {
	if len(data) == 0 || len(data) > MaxWireFrameBytes {
		return ClientFrame{}, ErrMalformedMessagingFrame
	}
	var frame ClientFrame
	var seenVersion bool
	var payloadSeen bool
	for len(data) > 0 {
		number, wireType, n := protowire.ConsumeTag(data)
		if n < 0 {
			return ClientFrame{}, ErrMalformedMessagingFrame
		}
		data = data[n:]
		switch number {
		case 1:
			if seenVersion || wireType != protowire.VarintType {
				return ClientFrame{}, ErrMalformedMessagingFrame
			}
			seenVersion = true
			value, n := protowire.ConsumeVarint(data)
			if n < 0 || value > uint64(^uint32(0)) {
				return ClientFrame{}, ErrMalformedMessagingFrame
			}
			frame.ProtocolVersion = uint32(value)
			data = data[n:]
		case 2, 3, 4:
			if payloadSeen || wireType != protowire.BytesType {
				return ClientFrame{}, ErrMalformedMessagingFrame
			}
			payloadSeen = true
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return ClientFrame{}, ErrMalformedMessagingFrame
			}
			data = data[n:]
			switch number {
			case 2:
				auth, err := decodeAuthResponse(value)
				if err != nil {
					return ClientFrame{}, ErrMalformedMessagingFrame
				}
				frame.AuthResponse = &auth
			case 3:
				envelope, err := DecodeEnvelope(value)
				if err != nil {
					return ClientFrame{}, ErrMalformedMessagingFrame
				}
				frame.Send = &envelope
			case 4:
				ack, err := decodeDeliveryAck(value)
				if err != nil {
					return ClientFrame{}, ErrMalformedMessagingFrame
				}
				frame.Ack = &ack
			}
		default:
			n := protowire.ConsumeFieldValue(number, wireType, data)
			if n < 0 {
				return ClientFrame{}, ErrMalformedMessagingFrame
			}
			data = data[n:]
		}
	}
	if frame.ProtocolVersion != ProtocolVersion || !payloadSeen || clientPayloadCount(frame) != 1 {
		return ClientFrame{}, ErrMalformedMessagingFrame
	}
	return frame, nil
}

func EncodeServerFrame(frame ServerFrame) ([]byte, error) {
	if frame.ProtocolVersion != ProtocolVersion || serverPayloadCount(frame) != 1 {
		return nil, ErrMalformedMessagingFrame
	}
	var number protowire.Number
	var nested []byte
	var err error
	switch {
	case frame.AuthChallenge != nil:
		number = 2
		nested, err = encodeAuthChallenge(*frame.AuthChallenge)
	case frame.Authenticated:
		number = 3
		nested = nil
	case frame.Delivery != nil:
		number = 4
		nested, err = EncodeEnvelope(*frame.Delivery)
	case frame.SendAccepted != nil:
		number = 5
		nested, err = encodeSendAccepted(*frame.SendAccepted)
	case frame.Error != nil:
		number = 6
		nested, err = encodeMessagingError(*frame.Error)
	}
	if err != nil {
		return nil, ErrMalformedMessagingFrame
	}
	out := appendVersion(nil)
	out = appendBytesField(out, number, nested)
	if len(out) > MaxWireFrameBytes {
		return nil, ErrMalformedMessagingFrame
	}
	return out, nil
}

func DecodeServerFrame(data []byte) (ServerFrame, error) {
	if len(data) == 0 || len(data) > MaxWireFrameBytes {
		return ServerFrame{}, ErrMalformedMessagingFrame
	}
	var frame ServerFrame
	var seenVersion bool
	var payloadSeen bool
	for len(data) > 0 {
		number, wireType, n := protowire.ConsumeTag(data)
		if n < 0 {
			return ServerFrame{}, ErrMalformedMessagingFrame
		}
		data = data[n:]
		switch number {
		case 1:
			if seenVersion || wireType != protowire.VarintType {
				return ServerFrame{}, ErrMalformedMessagingFrame
			}
			seenVersion = true
			value, n := protowire.ConsumeVarint(data)
			if n < 0 || value > uint64(^uint32(0)) {
				return ServerFrame{}, ErrMalformedMessagingFrame
			}
			frame.ProtocolVersion = uint32(value)
			data = data[n:]
		case 2, 3, 4, 5, 6:
			if payloadSeen || wireType != protowire.BytesType {
				return ServerFrame{}, ErrMalformedMessagingFrame
			}
			payloadSeen = true
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return ServerFrame{}, ErrMalformedMessagingFrame
			}
			data = data[n:]
			switch number {
			case 2:
				challenge, err := decodeAuthChallenge(value)
				if err != nil {
					return ServerFrame{}, ErrMalformedMessagingFrame
				}
				frame.AuthChallenge = &challenge
			case 3:
				if len(value) != 0 {
					return ServerFrame{}, ErrMalformedMessagingFrame
				}
				frame.Authenticated = true
			case 4:
				envelope, err := DecodeEnvelope(value)
				if err != nil {
					return ServerFrame{}, ErrMalformedMessagingFrame
				}
				frame.Delivery = &envelope
			case 5:
				accepted, err := decodeSendAccepted(value)
				if err != nil {
					return ServerFrame{}, ErrMalformedMessagingFrame
				}
				frame.SendAccepted = &accepted
			case 6:
				protocolError, err := decodeMessagingError(value)
				if err != nil {
					return ServerFrame{}, ErrMalformedMessagingFrame
				}
				frame.Error = &protocolError
			}
		default:
			n := protowire.ConsumeFieldValue(number, wireType, data)
			if n < 0 {
				return ServerFrame{}, ErrMalformedMessagingFrame
			}
			data = data[n:]
		}
	}
	if frame.ProtocolVersion != ProtocolVersion || !payloadSeen || serverPayloadCount(frame) != 1 {
		return ServerFrame{}, ErrMalformedMessagingFrame
	}
	return frame, nil
}

func encodeAuthChallenge(challenge AuthChallenge) ([]byte, error) {
	if challenge.ProtocolVersion != ProtocolVersion || !validChallenge(challenge.Challenge) || challenge.ExpiresAtUnixSeconds <= 0 {
		return nil, ErrMalformedMessagingFrame
	}
	out := appendVersion(nil)
	out = appendBytesField(out, 2, challenge.Challenge)
	out = appendVarintField(out, 3, uint64(challenge.ExpiresAtUnixSeconds))
	return out, nil
}

func decodeAuthChallenge(data []byte) (AuthChallenge, error) {
	var value AuthChallenge
	seen, err := decodeFixedMessage(data, func(number protowire.Number, wireType protowire.Type, field []byte, scalar uint64) error {
		switch number {
		case 1:
			if wireType != protowire.VarintType || scalar > uint64(^uint32(0)) {
				return ErrMalformedMessagingFrame
			}
			value.ProtocolVersion = uint32(scalar)
		case 2:
			if wireType != protowire.BytesType {
				return ErrMalformedMessagingFrame
			}
			value.Challenge = bytes.Clone(field)
		case 3:
			if wireType != protowire.VarintType || scalar > uint64(^uint64(0)>>1) {
				return ErrMalformedMessagingFrame
			}
			value.ExpiresAtUnixSeconds = int64(scalar)
		}
		return nil
	})
	if err != nil || seen != 0b111 || value.ProtocolVersion != ProtocolVersion || !validChallenge(value.Challenge) || value.ExpiresAtUnixSeconds <= 0 {
		return AuthChallenge{}, ErrMalformedMessagingFrame
	}
	return value, nil
}

func encodeAuthResponse(response AuthResponse) ([]byte, error) {
	if err := ValidateAuthResponseShape(response); err != nil {
		return nil, ErrMalformedMessagingFrame
	}
	out := appendVersion(nil)
	out = appendBytesField(out, 2, response.IdentityID)
	out = appendBytesField(out, 3, response.Challenge)
	out = appendVarintField(out, 4, uint64(response.ExpiresAtUnixSeconds))
	out = appendBytesField(out, 5, response.Signature)
	return out, nil
}

func decodeAuthResponse(data []byte) (AuthResponse, error) {
	var value AuthResponse
	seen, err := decodeFixedMessage(data, func(number protowire.Number, wireType protowire.Type, field []byte, scalar uint64) error {
		switch number {
		case 1:
			if wireType != protowire.VarintType || scalar > uint64(^uint32(0)) {
				return ErrMalformedMessagingFrame
			}
			value.ProtocolVersion = uint32(scalar)
		case 2:
			if wireType != protowire.BytesType {
				return ErrMalformedMessagingFrame
			}
			value.IdentityID = bytes.Clone(field)
		case 3:
			if wireType != protowire.BytesType {
				return ErrMalformedMessagingFrame
			}
			value.Challenge = bytes.Clone(field)
		case 4:
			if wireType != protowire.VarintType || scalar > uint64(^uint64(0)>>1) {
				return ErrMalformedMessagingFrame
			}
			value.ExpiresAtUnixSeconds = int64(scalar)
		case 5:
			if wireType != protowire.BytesType {
				return ErrMalformedMessagingFrame
			}
			value.Signature = bytes.Clone(field)
		}
		return nil
	})
	if err != nil || seen != 0b1_1111 || ValidateAuthResponseShape(value) != nil {
		return AuthResponse{}, ErrMalformedMessagingFrame
	}
	return value, nil
}

func encodeDeliveryAck(ack DeliveryAck) ([]byte, error) {
	if ack.ProtocolVersion != ProtocolVersion || len(ack.SenderIdentityID) != IdentityIDBytes || !validMessageID(ack.MessageID) {
		return nil, ErrMalformedMessagingFrame
	}
	out := appendVersion(nil)
	out = appendBytesField(out, 2, ack.SenderIdentityID)
	out = appendBytesField(out, 3, ack.MessageID)
	return out, nil
}

func decodeDeliveryAck(data []byte) (DeliveryAck, error) {
	var value DeliveryAck
	seen, err := decodeFixedMessage(data, func(number protowire.Number, wireType protowire.Type, field []byte, scalar uint64) error {
		switch number {
		case 1:
			if wireType != protowire.VarintType || scalar > uint64(^uint32(0)) {
				return ErrMalformedMessagingFrame
			}
			value.ProtocolVersion = uint32(scalar)
		case 2:
			if wireType != protowire.BytesType {
				return ErrMalformedMessagingFrame
			}
			value.SenderIdentityID = bytes.Clone(field)
		case 3:
			if wireType != protowire.BytesType {
				return ErrMalformedMessagingFrame
			}
			value.MessageID = bytes.Clone(field)
		}
		return nil
	})
	if err != nil || seen != 0b111 || value.ProtocolVersion != ProtocolVersion || len(value.SenderIdentityID) != IdentityIDBytes || !validMessageID(value.MessageID) {
		return DeliveryAck{}, ErrMalformedMessagingFrame
	}
	return value, nil
}

func encodeSendAccepted(accepted SendAccepted) ([]byte, error) {
	if accepted.ProtocolVersion != ProtocolVersion || len(accepted.RecipientIdentityID) != IdentityIDBytes || !validMessageID(accepted.MessageID) {
		return nil, ErrMalformedMessagingFrame
	}
	out := appendVersion(nil)
	out = appendBytesField(out, 2, accepted.RecipientIdentityID)
	out = appendBytesField(out, 3, accepted.MessageID)
	return out, nil
}

func decodeSendAccepted(data []byte) (SendAccepted, error) {
	var value SendAccepted
	seen, err := decodeFixedMessage(data, func(number protowire.Number, wireType protowire.Type, field []byte, scalar uint64) error {
		switch number {
		case 1:
			if wireType != protowire.VarintType || scalar > uint64(^uint32(0)) {
				return ErrMalformedMessagingFrame
			}
			value.ProtocolVersion = uint32(scalar)
		case 2:
			if wireType != protowire.BytesType {
				return ErrMalformedMessagingFrame
			}
			value.RecipientIdentityID = bytes.Clone(field)
		case 3:
			if wireType != protowire.BytesType {
				return ErrMalformedMessagingFrame
			}
			value.MessageID = bytes.Clone(field)
		}
		return nil
	})
	if err != nil || seen != 0b111 || value.ProtocolVersion != ProtocolVersion || len(value.RecipientIdentityID) != IdentityIDBytes || !validMessageID(value.MessageID) {
		return SendAccepted{}, ErrMalformedMessagingFrame
	}
	return value, nil
}

func encodeMessagingError(protocolError MessagingError) ([]byte, error) {
	if protocolError.ProtocolVersion != ProtocolVersion || !validErrorCode(protocolError.Code) || (len(protocolError.MessageID) != 0 && !validMessageID(protocolError.MessageID)) {
		return nil, ErrMalformedMessagingFrame
	}
	out := appendVersion(nil)
	out = appendVarintField(out, 2, uint64(protocolError.Code))
	if len(protocolError.MessageID) != 0 {
		out = appendBytesField(out, 3, protocolError.MessageID)
	}
	return out, nil
}

func decodeMessagingError(data []byte) (MessagingError, error) {
	var value MessagingError
	seen, err := decodeFixedMessage(data, func(number protowire.Number, wireType protowire.Type, field []byte, scalar uint64) error {
		switch number {
		case 1:
			if wireType != protowire.VarintType || scalar > uint64(^uint32(0)) {
				return ErrMalformedMessagingFrame
			}
			value.ProtocolVersion = uint32(scalar)
		case 2:
			if wireType != protowire.VarintType || scalar > uint64(^uint32(0)) {
				return ErrMalformedMessagingFrame
			}
			value.Code = MessagingErrorCode(scalar)
		case 3:
			if wireType != protowire.BytesType {
				return ErrMalformedMessagingFrame
			}
			value.MessageID = bytes.Clone(field)
		}
		return nil
	})
	if err != nil || seen&0b11 != 0b11 || value.ProtocolVersion != ProtocolVersion || !validErrorCode(value.Code) || (len(value.MessageID) != 0 && !validMessageID(value.MessageID)) {
		return MessagingError{}, ErrMalformedMessagingFrame
	}
	return value, nil
}

func decodeFixedMessage(data []byte, assign func(protowire.Number, protowire.Type, []byte, uint64) error) (uint64, error) {
	var seen uint64
	for len(data) > 0 {
		number, wireType, n := protowire.ConsumeTag(data)
		if n < 0 || number <= 0 || number > 63 {
			return 0, ErrMalformedMessagingFrame
		}
		data = data[n:]
		mask := uint64(1) << (number - 1)
		if seen&mask != 0 {
			return 0, ErrMalformedMessagingFrame
		}
		seen |= mask
		switch wireType {
		case protowire.VarintType:
			value, n := protowire.ConsumeVarint(data)
			if n < 0 {
				return 0, ErrMalformedMessagingFrame
			}
			if err := assign(number, wireType, nil, value); err != nil {
				return 0, err
			}
			data = data[n:]
		case protowire.BytesType:
			value, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return 0, ErrMalformedMessagingFrame
			}
			if err := assign(number, wireType, value, 0); err != nil {
				return 0, err
			}
			data = data[n:]
		default:
			n := protowire.ConsumeFieldValue(number, wireType, data)
			if n < 0 {
				return 0, ErrMalformedMessagingFrame
			}
			data = data[n:]
		}
	}
	return seen, nil
}

func appendVersion(out []byte) []byte {
	return appendVarintField(out, 1, uint64(ProtocolVersion))
}

func appendVarintField(out []byte, number protowire.Number, value uint64) []byte {
	out = protowire.AppendTag(out, number, protowire.VarintType)
	return protowire.AppendVarint(out, value)
}

func appendBytesField(out []byte, number protowire.Number, value []byte) []byte {
	out = protowire.AppendTag(out, number, protowire.BytesType)
	return protowire.AppendBytes(out, value)
}

func clientPayloadCount(frame ClientFrame) int {
	count := 0
	if frame.AuthResponse != nil {
		count++
	}
	if frame.Send != nil {
		count++
	}
	if frame.Ack != nil {
		count++
	}
	return count
}

func serverPayloadCount(frame ServerFrame) int {
	count := 0
	if frame.AuthChallenge != nil {
		count++
	}
	if frame.Authenticated {
		count++
	}
	if frame.Delivery != nil {
		count++
	}
	if frame.SendAccepted != nil {
		count++
	}
	if frame.Error != nil {
		count++
	}
	return count
}

func validErrorCode(code MessagingErrorCode) bool {
	return code >= MessagingErrorMalformed && code <= MessagingErrorRetryLater
}
