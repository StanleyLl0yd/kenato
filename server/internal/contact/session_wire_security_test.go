package contact

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestSessionWireRejectsOversizedAndMalformedMessages(t *testing.T) {
	oversized := make([]byte, MaxSessionWireMessageBytes+1)
	if _, err := DecodePublishSessionBootstrapRequest(oversized); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("oversized publish error=%v", err)
	}
	if _, err := DecodeReserveSessionBootstrapRequest([]byte{0x80}); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("truncated varint error=%v", err)
	}
	if _, err := DecodeClaimSessionInitRequest([]byte{0}); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("field-zero tag error=%v", err)
	}
}

func TestSessionWireRejectsDuplicateSingularAndWrongWireType(t *testing.T) {
	var duplicate []byte
	duplicate = protowire.AppendTag(duplicate, 1, protowire.VarintType)
	duplicate = protowire.AppendVarint(duplicate, uint64(SessionProtocolVersion))
	duplicate = protowire.AppendTag(duplicate, 1, protowire.VarintType)
	duplicate = protowire.AppendVarint(duplicate, uint64(SessionProtocolVersion))
	if _, err := DecodeReserveSessionBootstrapRequest(duplicate); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("duplicate version error=%v", err)
	}

	var wrongType []byte
	wrongType = protowire.AppendTag(wrongType, 1, protowire.BytesType)
	wrongType = protowire.AppendBytes(wrongType, []byte{1})
	if _, err := DecodeSubmitSessionInitRequest(wrongType); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("wrong wire type error=%v", err)
	}
}

func TestSessionBootstrapWireRejectsMoreThanMaximumOneTimeKeys(t *testing.T) {
	bundle := SessionBootstrapBundle{
		IdentityID:               bytes.Repeat([]byte{1}, IdentityIDBytes),
		AccountGeneration:        1,
		PublicationRevision:      1,
		OlmEd25519IdentityKey:    bytes.Repeat([]byte{2}, OlmPublicKeyBytes),
		OlmCurve25519IdentityKey: bytes.Repeat([]byte{3}, OlmPublicKeyBytes),
		BindingSignature:         []byte{1},
	}
	for i := 0; i < MaxSessionOneTimePreKeys; i++ {
		key := make([]byte, OlmPublicKeyBytes)
		key[0] = byte(i + 1)
		bundle.OneTimePreKeys = append(bundle.OneTimePreKeys, SessionOneTimePreKey{ID: uint64(i + 1), PublicKey: key})
	}
	encoded, err := EncodeSessionBootstrapBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	extraKey, err := encodeSessionOneTimePreKey(SessionOneTimePreKey{ID: MaxSessionOneTimePreKeys + 1, PublicKey: bytes.Repeat([]byte{0x7f}, OlmPublicKeyBytes)})
	if err != nil {
		t.Fatal(err)
	}
	encoded = protowire.AppendTag(encoded, 6, protowire.BytesType)
	encoded = protowire.AppendBytes(encoded, extraKey)

	if _, err := DecodeSessionBootstrapBundle(encoded); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("too many session OTKs error=%v", err)
	}
}

func TestSessionWireUnknownGroupsFailClosed(t *testing.T) {
	var message []byte
	message = protowire.AppendTag(message, 1, protowire.VarintType)
	message = protowire.AppendVarint(message, uint64(SessionProtocolVersion))
	message = protowire.AppendTag(message, 99, protowire.StartGroupType)
	if _, err := DecodeClaimSessionInitRequest(message); !errors.Is(err, ErrMalformedWire) {
		t.Fatalf("unknown group error=%v", err)
	}
}
