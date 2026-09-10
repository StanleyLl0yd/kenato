package contact

import (
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestPublicIdentityBundleWireRoundTrip(t *testing.T) {
	bundle, _ := newSignedBundle(t, 3)
	encoded, err := EncodePublicIdentityBundle(bundle)
	if err != nil {
		t.Fatalf("EncodePublicIdentityBundle: %v", err)
	}
	decoded, err := DecodePublicIdentityBundle(encoded)
	if err != nil {
		t.Fatalf("DecodePublicIdentityBundle: %v", err)
	}
	if !reflect.DeepEqual(decoded, bundle) {
		t.Fatalf("round trip mismatch\n got: %#v\nwant: %#v", decoded, bundle)
	}
	if err := ValidatePublicIdentityBundle(decoded); err != nil {
		t.Fatalf("round-tripped bundle failed validation: %v", err)
	}
}

func TestDecodePublishIdentityRequestAllowsUnknownFields(t *testing.T) {
	bundle, _ := newSignedBundle(t, 1)
	encodedBundle, err := EncodePublicIdentityBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var encoded []byte
	encoded = appendUint32Field(encoded, 1, ProtocolVersion)
	encoded = appendBytesField(encoded, 2, encodedBundle)
	encoded = appendUint32Field(encoded, 99, 7)

	request, err := DecodePublishIdentityRequest(encoded)
	if err != nil {
		t.Fatalf("DecodePublishIdentityRequest: %v", err)
	}
	if request.ProtocolVersion != ProtocolVersion || !reflect.DeepEqual(request.Bundle, bundle) {
		t.Fatal("decoded publish request mismatch")
	}
}

func TestDecodeRejectsDuplicateSingularFields(t *testing.T) {
	var encoded []byte
	encoded = appendUint32Field(encoded, 1, ProtocolVersion)
	encoded = appendUint32Field(encoded, 1, ProtocolVersion)
	if _, err := DecodePublishIdentityRequest(encoded); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("error = %v, want ErrMalformedWire", err)
	}
}

func TestDecodeRejectsWrongWireType(t *testing.T) {
	var encoded []byte
	encoded = protowire.AppendTag(encoded, 1, protowire.BytesType)
	encoded = protowire.AppendBytes(encoded, []byte{1})
	if _, err := DecodePublishIdentityRequest(encoded); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("error = %v, want ErrMalformedWire", err)
	}
}

func TestDecodeBundleRejectsTooManyOneTimePrekeys(t *testing.T) {
	var encoded []byte
	for i := 0; i < MaxOneTimePreKeys+1; i++ {
		encoded = appendBytesField(encoded, 5, []byte{})
	}
	if _, err := DecodePublicIdentityBundle(encoded); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("error = %v, want ErrMalformedWire", err)
	}
}

func TestDecodeRejectsOversizedMessage(t *testing.T) {
	if _, err := DecodePublishIdentityRequest(make([]byte, MaxWireMessageBytes+1)); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("error = %v, want ErrMalformedWire", err)
	}
}

func TestInviteRequestWireDecoding(t *testing.T) {
	creator, creatorKey := newSignedBundle(t, 0)
	token := make([]byte, InviteTokenBytes)
	for i := range token {
		token[i] = byte(i)
	}
	payload, err := InvitePayload(creator.IdentityID, token)
	if err != nil {
		t.Fatal(err)
	}
	invite := InviteDescriptor{
		CreatorIdentityID: creator.IdentityID,
		InviteToken:       token,
		InviteSignature:   signPayload(t, creatorKey, payload),
	}
	encodedInvite, err := encodeInviteDescriptor(invite)
	if err != nil {
		t.Fatal(err)
	}
	var encoded []byte
	encoded = appendUint32Field(encoded, 1, ProtocolVersion)
	encoded = appendBytesField(encoded, 2, encodedInvite)
	request, err := DecodeCreateInviteRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeCreateInviteRequest: %v", err)
	}
	if !reflect.DeepEqual(request.Invite, invite) {
		t.Fatal("decoded invite request mismatch")
	}
}
