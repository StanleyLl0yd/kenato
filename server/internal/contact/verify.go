package contact

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

func ValidatePublicIdentityBundle(bundle PublicIdentityBundle) error {
	if err := validateSignedBundleShape(bundle); err != nil {
		return err
	}

	identityKey, err := parseP256PublicKey(bundle.IdentityPublicKey)
	if err != nil {
		return fmt.Errorf("%w: identity public key", ErrInvalidBundle)
	}
	expectedID := sha256.Sum256(bundle.IdentityPublicKey)
	if !bytes.Equal(bundle.IdentityID, expectedID[:]) {
		return fmt.Errorf("%w: identity id mismatch", ErrInvalidBundle)
	}

	if _, err := parseP256PublicKey(bundle.SignedPreKey.PublicKey); err != nil {
		return fmt.Errorf("%w: signed prekey public key", ErrInvalidBundle)
	}
	for _, preKey := range bundle.OneTimePreKeys {
		if _, err := parseP256PublicKey(preKey.PublicKey); err != nil {
			return fmt.Errorf("%w: one-time prekey public key", ErrInvalidBundle)
		}
	}

	signedPreKeyPayload, err := SignedPreKeyPayload(bundle.SignedPreKey)
	if err != nil || !verifyP256Signature(identityKey, signedPreKeyPayload, bundle.SignedPreKey.Signature) {
		return fmt.Errorf("%w: signed prekey signature", ErrInvalidBundle)
	}

	publicationPayload, err := PublicationPayload(bundle)
	if err != nil || !verifyP256Signature(identityKey, publicationPayload, bundle.PublicationSignature) {
		return fmt.Errorf("%w: publication signature", ErrInvalidBundle)
	}
	return nil
}

func VerifyInviteDescriptor(invite InviteDescriptor, creatorPublicKey []byte) error {
	if err := validateInviteShape(invite); err != nil {
		return err
	}
	creatorKey, err := signerKey(invite.CreatorIdentityID, creatorPublicKey)
	if err != nil {
		return ErrInvalidInvite
	}
	payload, err := InvitePayload(invite.CreatorIdentityID, invite.InviteToken)
	if err != nil || !verifyP256Signature(creatorKey, payload, invite.InviteSignature) {
		return ErrInvalidInvite
	}
	return nil
}

func VerifyRedemptionProof(creatorIdentityID, redeemerIdentityID, inviteToken, signature, redeemerPublicKey []byte) error {
	if !validSignature(signature) {
		return ErrInvalidInvite
	}
	redeemerKey, err := signerKey(redeemerIdentityID, redeemerPublicKey)
	if err != nil {
		return ErrInvalidInvite
	}
	payload, err := RedemptionPayload(creatorIdentityID, redeemerIdentityID, inviteToken)
	if err != nil || !verifyP256Signature(redeemerKey, payload, signature) {
		return ErrInvalidInvite
	}
	return nil
}

func VerifyClaimProof(creatorIdentityID, inviteToken, signature, creatorPublicKey []byte) error {
	if !validSignature(signature) {
		return ErrInvalidInvite
	}
	creatorKey, err := signerKey(creatorIdentityID, creatorPublicKey)
	if err != nil {
		return ErrInvalidInvite
	}
	payload, err := ClaimPayload(creatorIdentityID, inviteToken)
	if err != nil || !verifyP256Signature(creatorKey, payload, signature) {
		return ErrInvalidInvite
	}
	return nil
}

func signerKey(identityID, publicKey []byte) (*ecdsa.PublicKey, error) {
	if len(identityID) != IdentityIDBytes || !validPublicKeyBytes(publicKey) {
		return nil, ErrInvalidBundle
	}
	expectedID := sha256.Sum256(publicKey)
	if !bytes.Equal(identityID, expectedID[:]) {
		return nil, ErrInvalidBundle
	}
	return parseP256PublicKey(publicKey)
}

func parseP256PublicKey(encoded []byte) (*ecdsa.PublicKey, error) {
	if !validPublicKeyBytes(encoded) {
		return nil, ErrInvalidBundle
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve == nil || publicKey.X == nil || publicKey.Y == nil {
		return nil, ErrInvalidBundle
	}
	p256 := elliptic.P256()
	if publicKey.Curve.Params().Name != p256.Params().Name || !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, ErrInvalidBundle
	}
	canonical, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, ErrInvalidBundle
	}
	return publicKey, nil
}

func verifyP256Signature(publicKey *ecdsa.PublicKey, payload, signature []byte) bool {
	if publicKey == nil || len(payload) == 0 || !validSignature(signature) {
		return false
	}
	digest := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(publicKey, digest[:], signature)
}
