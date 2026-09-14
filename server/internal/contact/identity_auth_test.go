package contact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

type identityAuthStore struct {
	encoded []byte
}

func (s identityAuthStore) PublishIdentity(context.Context, PublicationRecord) (uint64, error) {
	return 0, errors.New("unexpected PublishIdentity")
}

func (s identityAuthStore) GetIdentity(context.Context, []byte) (StoredIdentity, error) {
	return StoredIdentity{EncodedBundle: bytes.Clone(s.encoded)}, nil
}

func (s identityAuthStore) CreateInvite(context.Context, [sha256.Size]byte, []byte, int64, int64) (int64, error) {
	return 0, errors.New("unexpected CreateInvite")
}

func (s identityAuthStore) RedeemInvite(context.Context, RedeemRecord) (RedeemResult, error) {
	return RedeemResult{}, errors.New("unexpected RedeemInvite")
}

func (s identityAuthStore) ClaimInvite(context.Context, ClaimRecord) (ClaimResult, error) {
	return ClaimResult{}, errors.New("unexpected ClaimInvite")
}

func TestVerifyIdentitySignatureUsesPublishedCanonicalIdentity(t *testing.T) {
	bundle, privateKey := newSignedBundle(t, 0)
	encoded, err := EncodePublicIdentityBundle(bundle)
	if err != nil {
		t.Fatalf("EncodePublicIdentityBundle: %v", err)
	}
	service := NewService(identityAuthStore{encoded: encoded})
	payload := []byte("KENATO-MESSAGING-AUTH-V1-test-payload")
	signature := signPayload(t, privateKey, payload)

	if err := service.VerifyIdentitySignature(context.Background(), bundle.IdentityID, payload, signature); err != nil {
		t.Fatalf("valid identity signature rejected: %v", err)
	}
	if err := service.VerifyIdentitySignature(context.Background(), bundle.IdentityID, append(bytes.Clone(payload), 1), signature); err == nil {
		t.Fatal("signature accepted for altered payload")
	}
	wrongIdentity := bytes.Clone(bundle.IdentityID)
	wrongIdentity[0] ^= 0xff
	if err := service.VerifyIdentitySignature(context.Background(), wrongIdentity, payload, signature); err == nil {
		t.Fatal("signature accepted for a different identity id")
	}
}
