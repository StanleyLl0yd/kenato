package contact

import "fmt"

func ValidateSessionBootstrapBundle(bundle SessionBootstrapBundle, identityPublicKey []byte) error {
	if err := validateSessionBootstrapShape(bundle, true); err != nil {
		return err
	}
	identityKey, err := signerKey(bundle.IdentityID, identityPublicKey)
	if err != nil {
		return ErrInvalidSessionBootstrap
	}
	payload, err := SessionBootstrapPayload(bundle)
	if err != nil || !verifyP256Signature(identityKey, payload, bundle.BindingSignature) {
		return fmt.Errorf("%w: binding signature", ErrInvalidSessionBootstrap)
	}
	return nil
}

func VerifySessionReserveProof(request ReserveSessionBootstrapRequest, redeemerPublicKey []byte) error {
	if request.ProtocolVersion != SessionProtocolVersion || !validSignature(request.ReserveSignature) {
		return ErrInvalidSessionBootstrap
	}
	key, err := signerKey(request.RedeemerIdentityID, redeemerPublicKey)
	if err != nil {
		return ErrInvalidSessionBootstrap
	}
	payload, err := SessionReservePayload(request.CreatorIdentityID, request.RedeemerIdentityID, request.InviteToken)
	if err != nil || !verifyP256Signature(key, payload, request.ReserveSignature) {
		return ErrInvalidSessionBootstrap
	}
	return nil
}

func VerifySessionSubmitProof(request SubmitSessionInitRequest, redeemerPublicKey []byte) error {
	if request.ProtocolVersion != SessionProtocolVersion {
		return ErrInvalidSessionBootstrap
	}
	key, err := signerKey(request.RedeemerIdentityID, redeemerPublicKey)
	if err != nil {
		return ErrInvalidSessionBootstrap
	}
	payload, err := SessionSubmitPayload(request)
	if err != nil || !verifyP256Signature(key, payload, request.SubmitSignature) {
		return ErrInvalidSessionBootstrap
	}
	return nil
}

func VerifySessionClaimProof(request ClaimSessionInitRequest, creatorPublicKey []byte) error {
	if request.ProtocolVersion != SessionProtocolVersion || !validSignature(request.ClaimSignature) {
		return ErrInvalidSessionBootstrap
	}
	key, err := signerKey(request.CreatorIdentityID, creatorPublicKey)
	if err != nil {
		return ErrInvalidSessionBootstrap
	}
	payload, err := SessionClaimPayload(request.CreatorIdentityID, request.InviteToken)
	if err != nil || !verifyP256Signature(key, payload, request.ClaimSignature) {
		return ErrInvalidSessionBootstrap
	}
	return nil
}
