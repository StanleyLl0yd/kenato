package contact

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
)

var (
	sessionBootstrapDomain   = []byte("KENATO-SESSION-BOOTSTRAP-V1\x00")
	sessionReserveDomain     = []byte("KENATO-SESSION-RESERVE-V1\x00")
	sessionSubmitDomain      = []byte("KENATO-SESSION-INIT-SUBMIT-V1\x00")
	sessionClaimDomain       = []byte("KENATO-SESSION-CLAIM-V1\x00")
	sessionInitControlDomain = []byte("KENATO-SESSION-INIT-CONTROL-V1\x00")
)

func SessionBootstrapPayload(bundle SessionBootstrapBundle) ([]byte, error) {
	if err := validateSessionBootstrapShape(bundle, false); err != nil {
		return nil, err
	}
	capacity := len(sessionBootstrapDomain) + IdentityIDBytes + 8 + 8 + 2*OlmPublicKeyBytes + 4 + len(bundle.OneTimePreKeys)*(8+OlmPublicKeyBytes)
	payload := make([]byte, 0, capacity)
	payload = append(payload, sessionBootstrapDomain...)
	payload = append(payload, bundle.IdentityID...)
	payload = binary.BigEndian.AppendUint64(payload, bundle.AccountGeneration)
	payload = binary.BigEndian.AppendUint64(payload, bundle.PublicationRevision)
	payload = append(payload, bundle.OlmEd25519IdentityKey...)
	payload = append(payload, bundle.OlmCurve25519IdentityKey...)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(bundle.OneTimePreKeys)))
	for _, key := range bundle.OneTimePreKeys {
		payload = binary.BigEndian.AppendUint64(payload, key.ID)
		payload = append(payload, key.PublicKey...)
	}
	return payload, nil
}

func SessionReservePayload(creatorIdentityID, redeemerIdentityID, inviteToken []byte) ([]byte, error) {
	if len(creatorIdentityID) != IdentityIDBytes || len(redeemerIdentityID) != IdentityIDBytes || len(inviteToken) != InviteTokenBytes || bytes.Equal(creatorIdentityID, redeemerIdentityID) {
		return nil, ErrInvalidSessionBootstrap
	}
	payload := make([]byte, 0, len(sessionReserveDomain)+2*IdentityIDBytes+InviteTokenBytes)
	payload = append(payload, sessionReserveDomain...)
	payload = append(payload, creatorIdentityID...)
	payload = append(payload, redeemerIdentityID...)
	payload = append(payload, inviteToken...)
	return payload, nil
}

func SessionSubmitPayload(request SubmitSessionInitRequest) ([]byte, error) {
	// The signature is intentionally not part of shape validation here: this
	// canonical payload is what the caller signs. Signature validation happens
	// at the verification/service boundary after the payload exists.
	if err := validateSessionInitPayloadShape(request); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(request.OlmMessage)
	payload := make([]byte, 0, len(sessionSubmitDomain)+2*IdentityIDBytes+InviteTokenBytes+8+8+8+4+sha256.Size)
	payload = append(payload, sessionSubmitDomain...)
	payload = append(payload, request.CreatorIdentityID...)
	payload = append(payload, request.RedeemerIdentityID...)
	payload = append(payload, request.InviteToken...)
	payload = binary.BigEndian.AppendUint64(payload, request.CreatorAccountGeneration)
	payload = binary.BigEndian.AppendUint64(payload, request.CreatorOneTimePreKeyID)
	payload = binary.BigEndian.AppendUint64(payload, request.RedeemerAccountGeneration)
	payload = binary.BigEndian.AppendUint32(payload, request.OlmMessageType)
	payload = append(payload, digest[:]...)
	return payload, nil
}

// SessionInitControlPayload is the exact plaintext placed inside the first Olm
// pre-key frame. The server never parses these bytes; both peers use the
// domain-separated binding to prevent a valid frame from being transplanted to
// a different invite, contact, account generation, or creator OTK.
func SessionInitControlPayload(
	creatorIdentityID,
	redeemerIdentityID,
	inviteToken []byte,
	creatorAccountGeneration,
	creatorOneTimePreKeyID,
	redeemerAccountGeneration uint64,
) ([]byte, error) {
	if len(creatorIdentityID) != IdentityIDBytes || len(redeemerIdentityID) != IdentityIDBytes || len(inviteToken) != InviteTokenBytes || bytes.Equal(creatorIdentityID, redeemerIdentityID) {
		return nil, ErrInvalidSessionBootstrap
	}
	if creatorAccountGeneration == 0 || creatorAccountGeneration > math.MaxInt64 ||
		creatorOneTimePreKeyID == 0 || creatorOneTimePreKeyID > math.MaxInt64 ||
		redeemerAccountGeneration == 0 || redeemerAccountGeneration > math.MaxInt64 {
		return nil, ErrInvalidSessionBootstrap
	}

	tokenHash := sha256.Sum256(inviteToken)
	payload := make([]byte, 0, len(sessionInitControlDomain)+2*IdentityIDBytes+sha256.Size+3*8)
	payload = append(payload, sessionInitControlDomain...)
	payload = append(payload, creatorIdentityID...)
	payload = append(payload, redeemerIdentityID...)
	payload = append(payload, tokenHash[:]...)
	payload = binary.BigEndian.AppendUint64(payload, creatorAccountGeneration)
	payload = binary.BigEndian.AppendUint64(payload, creatorOneTimePreKeyID)
	payload = binary.BigEndian.AppendUint64(payload, redeemerAccountGeneration)
	return payload, nil
}

func SessionClaimPayload(creatorIdentityID, inviteToken []byte) ([]byte, error) {
	if len(creatorIdentityID) != IdentityIDBytes || len(inviteToken) != InviteTokenBytes {
		return nil, ErrInvalidSessionBootstrap
	}
	payload := make([]byte, 0, len(sessionClaimDomain)+IdentityIDBytes+InviteTokenBytes)
	payload = append(payload, sessionClaimDomain...)
	payload = append(payload, creatorIdentityID...)
	payload = append(payload, inviteToken...)
	return payload, nil
}

func validateSessionBootstrapShape(bundle SessionBootstrapBundle, requireSignature bool) error {
	if len(bundle.IdentityID) != IdentityIDBytes || bundle.AccountGeneration == 0 || bundle.AccountGeneration > math.MaxInt64 || bundle.PublicationRevision == 0 || bundle.PublicationRevision > math.MaxInt64 {
		return ErrInvalidSessionBootstrap
	}
	if len(bundle.OlmEd25519IdentityKey) != OlmPublicKeyBytes || len(bundle.OlmCurve25519IdentityKey) != OlmPublicKeyBytes || allZero(bundle.OlmEd25519IdentityKey) || allZero(bundle.OlmCurve25519IdentityKey) {
		return ErrInvalidSessionBootstrap
	}
	if bytes.Equal(bundle.OlmEd25519IdentityKey, bundle.OlmCurve25519IdentityKey) {
		return ErrInvalidSessionBootstrap
	}
	if len(bundle.OneTimePreKeys) == 0 || len(bundle.OneTimePreKeys) > MaxSessionOneTimePreKeys {
		return ErrInvalidSessionBootstrap
	}
	if requireSignature && !validSignature(bundle.BindingSignature) {
		return ErrInvalidSessionBootstrap
	}
	if !requireSignature && len(bundle.BindingSignature) > MaxSignatureBytes {
		return ErrInvalidSessionBootstrap
	}
	var previousID uint64
	seenKeys := make(map[string]struct{}, len(bundle.OneTimePreKeys))
	for _, key := range bundle.OneTimePreKeys {
		if key.ID == 0 || key.ID > math.MaxInt64 || key.ID <= previousID || len(key.PublicKey) != OlmPublicKeyBytes || allZero(key.PublicKey) {
			return ErrInvalidSessionBootstrap
		}
		if bytes.Equal(key.PublicKey, bundle.OlmEd25519IdentityKey) || bytes.Equal(key.PublicKey, bundle.OlmCurve25519IdentityKey) {
			return ErrInvalidSessionBootstrap
		}
		encoded := string(key.PublicKey)
		if _, duplicate := seenKeys[encoded]; duplicate {
			return ErrInvalidSessionBootstrap
		}
		seenKeys[encoded] = struct{}{}
		previousID = key.ID
	}
	return nil
}

func validateSessionInitShape(request SubmitSessionInitRequest) error {
	if err := validateSessionInitPayloadShape(request); err != nil {
		return err
	}
	if !validSignature(request.SubmitSignature) {
		return ErrInvalidSessionBootstrap
	}
	return nil
}

func validateSessionInitPayloadShape(request SubmitSessionInitRequest) error {
	if len(request.CreatorIdentityID) != IdentityIDBytes || len(request.RedeemerIdentityID) != IdentityIDBytes || bytes.Equal(request.CreatorIdentityID, request.RedeemerIdentityID) {
		return ErrInvalidSessionBootstrap
	}
	if len(request.InviteToken) != InviteTokenBytes || request.CreatorAccountGeneration == 0 || request.CreatorAccountGeneration > math.MaxInt64 || request.CreatorOneTimePreKeyID == 0 || request.CreatorOneTimePreKeyID > math.MaxInt64 || request.RedeemerAccountGeneration == 0 || request.RedeemerAccountGeneration > math.MaxInt64 {
		return ErrInvalidSessionBootstrap
	}
	if request.OlmMessageType != OlmMessageTypePreKey || len(request.OlmMessage) == 0 || len(request.OlmMessage) > MaxSessionCiphertextBytes {
		return ErrInvalidSessionBootstrap
	}
	return nil
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
