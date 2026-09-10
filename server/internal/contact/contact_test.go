package contact

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

func TestCanonicalPayloadVectors(t *testing.T) {
	creatorID := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	inviteToken := mustHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	redeemerID := mustHex(t, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")

	bundle := PublicIdentityBundle{
		IdentityID:          creatorID,
		IdentityPublicKey:   []byte{1, 2, 3},
		PublicationRevision: 3,
		SignedPreKey: SignedPreKey{
			ID:                   7,
			PublicKey:            []byte{4, 5, 6},
			Signature:            []byte{7, 8, 9},
			CreatedAtUnixSeconds: 10,
		},
		OneTimePreKeys: []OneTimePreKey{
			{ID: 8, CreatedAtUnixSeconds: 11, PublicKey: []byte{0x0a, 0x0b}},
			{ID: 9, CreatedAtUnixSeconds: 12, PublicKey: []byte{0x0c}},
		},
	}

	publication, err := PublicationPayload(bundle)
	if err != nil {
		t.Fatalf("PublicationPayload: %v", err)
	}
	assertHex(t, publication, "4b454e41544f2d5055424c49434154494f4e2d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000030000000301020300000007000000000000000a00000003040506000000030708090000000200000008000000000000000b000000020a0b00000009000000000000000c000000010c")

	invite, err := InvitePayload(creatorID, inviteToken)
	if err != nil {
		t.Fatalf("InvitePayload: %v", err)
	}
	assertHex(t, invite, "4b454e41544f2d494e564954452d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")

	redeem, err := RedemptionPayload(creatorID, redeemerID, inviteToken)
	if err != nil {
		t.Fatalf("RedemptionPayload: %v", err)
	}
	assertHex(t, redeem, "4b454e41544f2d52454445454d2d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")

	claim, err := ClaimPayload(creatorID, inviteToken)
	if err != nil {
		t.Fatalf("ClaimPayload: %v", err)
	}
	assertHex(t, claim, "4b454e41544f2d434c41494d2d563100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
}

func TestValidatePublicIdentityBundle(t *testing.T) {
	bundle, _ := newSignedBundle(t, 2)
	if err := ValidatePublicIdentityBundle(bundle); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
}

func TestValidatePublicIdentityBundleRejectsIdentityMismatch(t *testing.T) {
	bundle, _ := newSignedBundle(t, 1)
	bundle.IdentityID = bytes.Clone(bundle.IdentityID)
	bundle.IdentityID[0] ^= 0xff
	if err := ValidatePublicIdentityBundle(bundle); err == nil {
		t.Fatal("identity mismatch accepted")
	}
}

func TestValidatePublicIdentityBundleRejectsAlteredSignatures(t *testing.T) {
	t.Run("signed prekey", func(t *testing.T) {
		bundle, _ := newSignedBundle(t, 1)
		bundle.SignedPreKey.Signature = []byte{1}
		if err := ValidatePublicIdentityBundle(bundle); err == nil {
			t.Fatal("invalid signed-prekey signature accepted")
		}
	})

	t.Run("publication", func(t *testing.T) {
		bundle, _ := newSignedBundle(t, 1)
		bundle.PublicationSignature = []byte{1}
		if err := ValidatePublicIdentityBundle(bundle); err == nil {
			t.Fatal("invalid publication signature accepted")
		}
	})
}

func TestValidatePublicIdentityBundleRejectsNonCanonicalPrekeys(t *testing.T) {
	bundle, _ := newSignedBundle(t, 2)
	bundle.OneTimePreKeys[1].ID = bundle.OneTimePreKeys[0].ID
	if err := ValidatePublicIdentityBundle(bundle); err == nil {
		t.Fatal("duplicate one-time prekey id accepted")
	}
}

func TestValidatePublicIdentityBundleRejectsWrongCurve(t *testing.T) {
	bundle, _ := newSignedBundle(t, 0)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	bundle.IdentityPublicKey = marshalPublicKey(t, &wrongKey.PublicKey)
	wrongID := sha256.Sum256(bundle.IdentityPublicKey)
	bundle.IdentityID = wrongID[:]
	if err := ValidatePublicIdentityBundle(bundle); err == nil {
		t.Fatal("P-384 identity key accepted")
	}
}

func TestInviteAndContactProofVerification(t *testing.T) {
	creatorBundle, creatorKey := newSignedBundle(t, 0)
	redeemerBundle, redeemerKey := newSignedBundle(t, 0)
	inviteToken := make([]byte, InviteTokenBytes)
	if _, err := rand.Read(inviteToken); err != nil {
		t.Fatalf("generate invite token: %v", err)
	}

	invitePayload, err := InvitePayload(creatorBundle.IdentityID, inviteToken)
	if err != nil {
		t.Fatalf("InvitePayload: %v", err)
	}
	invite := InviteDescriptor{
		CreatorIdentityID: bytes.Clone(creatorBundle.IdentityID),
		InviteToken:       bytes.Clone(inviteToken),
		InviteSignature:   signPayload(t, creatorKey, invitePayload),
	}
	if err := VerifyInviteDescriptor(invite, creatorBundle.IdentityPublicKey); err != nil {
		t.Fatalf("valid invite rejected: %v", err)
	}

	redeemPayload, err := RedemptionPayload(creatorBundle.IdentityID, redeemerBundle.IdentityID, inviteToken)
	if err != nil {
		t.Fatalf("RedemptionPayload: %v", err)
	}
	redeemSignature := signPayload(t, redeemerKey, redeemPayload)
	if err := VerifyRedemptionProof(creatorBundle.IdentityID, redeemerBundle.IdentityID, inviteToken, redeemSignature, redeemerBundle.IdentityPublicKey); err != nil {
		t.Fatalf("valid redemption proof rejected: %v", err)
	}

	claimPayload, err := ClaimPayload(creatorBundle.IdentityID, inviteToken)
	if err != nil {
		t.Fatalf("ClaimPayload: %v", err)
	}
	claimSignature := signPayload(t, creatorKey, claimPayload)
	if err := VerifyClaimProof(creatorBundle.IdentityID, inviteToken, claimSignature, creatorBundle.IdentityPublicKey); err != nil {
		t.Fatalf("valid claim proof rejected: %v", err)
	}

	wrongToken := bytes.Clone(inviteToken)
	wrongToken[0] ^= 0xff
	if err := VerifyRedemptionProof(creatorBundle.IdentityID, redeemerBundle.IdentityID, wrongToken, redeemSignature, redeemerBundle.IdentityPublicKey); err == nil {
		t.Fatal("redemption proof accepted for a different token")
	}
}

func TestInviteTokenHashRequiresExactLength(t *testing.T) {
	if _, err := InviteTokenHash(make([]byte, InviteTokenBytes-1)); err == nil {
		t.Fatal("short invite token accepted")
	}
	token := make([]byte, InviteTokenBytes)
	hash, err := InviteTokenHash(token)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if hash != sha256.Sum256(token) {
		t.Fatal("unexpected invite token hash")
	}
}

func newSignedBundle(t *testing.T, oneTimeCount int) (PublicIdentityBundle, *ecdsa.PrivateKey) {
	t.Helper()
	identityKey := generateKey(t, elliptic.P256())
	identityPublicKey := marshalPublicKey(t, &identityKey.PublicKey)
	identityID := sha256.Sum256(identityPublicKey)

	signedPreKey := generateKey(t, elliptic.P256())
	signedPreKeyPublic := marshalPublicKey(t, &signedPreKey.PublicKey)
	bundle := PublicIdentityBundle{
		IdentityID:          bytes.Clone(identityID[:]),
		IdentityPublicKey:   identityPublicKey,
		PublicationRevision: 1,
		SignedPreKey: SignedPreKey{
			ID:                   1,
			PublicKey:            signedPreKeyPublic,
			CreatedAtUnixSeconds: 100,
		},
	}
	signedPreKeyPayload, err := SignedPreKeyPayload(bundle.SignedPreKey)
	if err != nil {
		t.Fatalf("SignedPreKeyPayload: %v", err)
	}
	bundle.SignedPreKey.Signature = signPayload(t, identityKey, signedPreKeyPayload)

	for i := 0; i < oneTimeCount; i++ {
		key := generateKey(t, elliptic.P256())
		bundle.OneTimePreKeys = append(bundle.OneTimePreKeys, OneTimePreKey{
			ID:                   uint32(i + 2),
			PublicKey:            marshalPublicKey(t, &key.PublicKey),
			CreatedAtUnixSeconds: int64(101 + i),
		})
	}
	publicationPayload, err := PublicationPayload(bundle)
	if err != nil {
		t.Fatalf("PublicationPayload: %v", err)
	}
	bundle.PublicationSignature = signPayload(t, identityKey, publicationPayload)
	return bundle, identityKey
}

func generateKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func marshalPublicKey(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return encoded
}

func signPayload(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}
	return signature
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

func assertHex(t *testing.T, actual []byte, expected string) {
	t.Helper()
	if hex.EncodeToString(actual) != expected {
		t.Fatalf("unexpected payload\n got: %x\nwant: %s", actual, expected)
	}
}
