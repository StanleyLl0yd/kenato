package contact

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestSessionInitControlPayloadVector(t *testing.T) {
	creator := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	redeemer := mustHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	token := mustHex(t, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")

	payload, err := SessionInitControlPayload(creator, redeemer, token, 2, 7, 4)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, payload, "4b454e41544f2d53455353494f4e2d494e49542d434f4e54524f4c2d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fca2a4fe727faaecf16ecd130a86e0885c5540c05375340445071c0657555fd42000000000000000200000000000000070000000000000004")
}

func TestSessionInitControlPayloadRejectsInvalidBindings(t *testing.T) {
	creator := bytes.Repeat([]byte{1}, IdentityIDBytes)
	redeemer := bytes.Repeat([]byte{2}, IdentityIDBytes)
	token := bytes.Repeat([]byte{3}, InviteTokenBytes)

	tests := map[string]struct {
		creator    []byte
		redeemer   []byte
		token      []byte
		creatorGen uint64
		keyID      uint64
		redeemerGen uint64
	}{
		"same identity":          {creator, creator, token, 1, 1, 1},
		"short creator":          {creator[:len(creator)-1], redeemer, token, 1, 1, 1},
		"short redeemer":         {creator, redeemer[:len(redeemer)-1], token, 1, 1, 1},
		"short token":            {creator, redeemer, token[:len(token)-1], 1, 1, 1},
		"zero creator generation": {creator, redeemer, token, 0, 1, 1},
		"zero key id":            {creator, redeemer, token, 1, 0, 1},
		"zero redeemer generation": {creator, redeemer, token, 1, 1, 0},
		"oversized generation":   {creator, redeemer, token, uint64(math.MaxInt64) + 1, 1, 1},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := SessionInitControlPayload(tc.creator, tc.redeemer, tc.token, tc.creatorGen, tc.keyID, tc.redeemerGen); !errors.Is(err, ErrInvalidSessionBootstrap) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidSessionBootstrap)
			}
		})
	}
}

func TestSessionBootstrapRejectsEngineAndOneTimeKeyAliasing(t *testing.T) {
	bundle := SessionBootstrapBundle{
		IdentityID:               bytes.Repeat([]byte{1}, IdentityIDBytes),
		AccountGeneration:        1,
		PublicationRevision:      1,
		OlmEd25519IdentityKey:    bytes.Repeat([]byte{2}, OlmPublicKeyBytes),
		OlmCurve25519IdentityKey: bytes.Repeat([]byte{3}, OlmPublicKeyBytes),
		OneTimePreKeys: []SessionOneTimePreKey{
			{ID: 1, PublicKey: bytes.Repeat([]byte{4}, OlmPublicKeyBytes)},
		},
	}

	t.Run("engine identity keys", func(t *testing.T) {
		aliased := cloneSessionBundle(bundle)
		aliased.OlmCurve25519IdentityKey = bytes.Clone(aliased.OlmEd25519IdentityKey)
		if _, err := SessionBootstrapPayload(aliased); !errors.Is(err, ErrInvalidSessionBootstrap) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidSessionBootstrap)
		}
	})

	t.Run("one-time key and curve identity", func(t *testing.T) {
		aliased := cloneSessionBundle(bundle)
		aliased.OneTimePreKeys[0].PublicKey = bytes.Clone(aliased.OlmCurve25519IdentityKey)
		if _, err := SessionBootstrapPayload(aliased); !errors.Is(err, ErrInvalidSessionBootstrap) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidSessionBootstrap)
		}
	})

	t.Run("one-time key and ed identity", func(t *testing.T) {
		aliased := cloneSessionBundle(bundle)
		aliased.OneTimePreKeys[0].PublicKey = bytes.Clone(aliased.OlmEd25519IdentityKey)
		if _, err := SessionBootstrapPayload(aliased); !errors.Is(err, ErrInvalidSessionBootstrap) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidSessionBootstrap)
		}
	})
}
