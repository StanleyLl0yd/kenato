package messaging

import (
	"bytes"
	"reflect"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestMessagingTransportFrameRoundTrips(t *testing.T) {
	sender := bytes.Repeat([]byte{0x11}, IdentityIDBytes)
	recipient := bytes.Repeat([]byte{0x22}, IdentityIDBytes)
	messageID := bytes.Repeat([]byte{0x33}, MessageIDBytes)
	challenge := bytes.Repeat([]byte{0x44}, AuthChallengeBytes)
	envelope := Envelope{
		ProtocolVersion:      ProtocolVersion,
		SenderIdentityID:     sender,
		RecipientIdentityID:  recipient,
		MessageID:            messageID,
		Ciphertext:           []byte{1, 2, 3, 4},
		ExpiresAtUnixSeconds: 12345,
	}

	clientFrames := []ClientFrame{
		{ProtocolVersion: ProtocolVersion, AuthResponse: &AuthResponse{ProtocolVersion: ProtocolVersion, IdentityID: sender, Challenge: challenge, ExpiresAtUnixSeconds: 123, Signature: []byte{0x30, 1}}},
		{ProtocolVersion: ProtocolVersion, Send: &envelope},
		{ProtocolVersion: ProtocolVersion, Ack: &DeliveryAck{ProtocolVersion: ProtocolVersion, SenderIdentityID: sender, MessageID: messageID}},
	}
	for _, want := range clientFrames {
		encoded, err := EncodeClientFrame(want)
		if err != nil {
			t.Fatalf("EncodeClientFrame: %v", err)
		}
		got, err := DecodeClientFrame(encoded)
		if err != nil {
			t.Fatalf("DecodeClientFrame: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("client frame round trip mismatch: got %#v want %#v", got, want)
		}
	}

	serverFrames := []ServerFrame{
		{ProtocolVersion: ProtocolVersion, AuthChallenge: &AuthChallenge{ProtocolVersion: ProtocolVersion, Challenge: challenge, ExpiresAtUnixSeconds: 123}},
		{ProtocolVersion: ProtocolVersion, Authenticated: true},
		{ProtocolVersion: ProtocolVersion, Delivery: &envelope},
		{ProtocolVersion: ProtocolVersion, SendAccepted: &SendAccepted{ProtocolVersion: ProtocolVersion, RecipientIdentityID: recipient, MessageID: messageID}},
		{ProtocolVersion: ProtocolVersion, Error: &MessagingError{ProtocolVersion: ProtocolVersion, Code: MessagingErrorRetryLater, MessageID: messageID}},
	}
	for _, want := range serverFrames {
		encoded, err := EncodeServerFrame(want)
		if err != nil {
			t.Fatalf("EncodeServerFrame: %v", err)
		}
		got, err := DecodeServerFrame(encoded)
		if err != nil {
			t.Fatalf("DecodeServerFrame: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("server frame round trip mismatch: got %#v want %#v", got, want)
		}
	}
}

func TestMessagingTransportRejectsDuplicateOrOversizedFrames(t *testing.T) {
	id := bytes.Repeat([]byte{0x11}, IdentityIDBytes)
	challenge := bytes.Repeat([]byte{0x22}, AuthChallengeBytes)
	auth := AuthResponse{ProtocolVersion: ProtocolVersion, IdentityID: id, Challenge: challenge, ExpiresAtUnixSeconds: 123, Signature: []byte{1}}
	nested, err := encodeAuthResponse(auth)
	if err != nil {
		t.Fatalf("encodeAuthResponse: %v", err)
	}

	duplicatePayload := appendVersion(nil)
	duplicatePayload = appendBytesField(duplicatePayload, 2, nested)
	duplicatePayload = appendBytesField(duplicatePayload, 2, nested)
	if _, err := DecodeClientFrame(duplicatePayload); err == nil {
		t.Fatal("duplicate client payload accepted")
	}

	duplicateNested := append([]byte(nil), nested...)
	duplicateNested = protowire.AppendTag(duplicateNested, 5, protowire.BytesType)
	duplicateNested = protowire.AppendBytes(duplicateNested, []byte{2})
	outer := appendVersion(nil)
	outer = appendBytesField(outer, 2, duplicateNested)
	if _, err := DecodeClientFrame(outer); err == nil {
		t.Fatal("duplicate nested auth signature accepted")
	}

	if _, err := DecodeClientFrame(make([]byte, MaxWireFrameBytes+1)); err == nil {
		t.Fatal("oversized client frame accepted")
	}
	if _, err := DecodeServerFrame(make([]byte, MaxWireFrameBytes+1)); err == nil {
		t.Fatal("oversized server frame accepted")
	}
}

func TestMessagingTransportRequiresExactlyOnePayload(t *testing.T) {
	if _, err := EncodeClientFrame(ClientFrame{ProtocolVersion: ProtocolVersion}); err == nil {
		t.Fatal("empty client frame accepted")
	}
	if _, err := EncodeServerFrame(ServerFrame{ProtocolVersion: ProtocolVersion}); err == nil {
		t.Fatal("empty server frame accepted")
	}

	messageID := bytes.Repeat([]byte{2}, MessageIDBytes)
	if _, err := EncodeServerFrame(ServerFrame{
		ProtocolVersion: ProtocolVersion,
		Authenticated:   true,
		Error: &MessagingError{
			ProtocolVersion: ProtocolVersion,
			Code:            MessagingErrorMalformed,
			MessageID:       messageID,
		},
	}); err == nil {
		t.Fatal("multi-payload server frame accepted")
	}
}
