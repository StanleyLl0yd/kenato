package contact

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

var (
	publicationDomain  = []byte("KENATO-PUBLICATION-V1\x00")
	signedPreKeyDomain = []byte("KENATO-SIGNED-PREKEY-V1\x00")
	inviteDomain       = []byte("KENATO-INVITE-V1\x00")
	redeemDomain       = []byte("KENATO-REDEEM-V1\x00")
	claimDomain        = []byte("KENATO-CLAIM-V1\x00")
)

func IdentityID(publicKey []byte) ([IdentityIDBytes]byte, error) {
	if len(publicKey) == 0 || len(publicKey) > MaxPublicKeyBytes {
		return [IdentityIDBytes]byte{}, fmt.Errorf("%w: identity public key size", ErrInvalidBundle)
	}
	return sha256.Sum256(publicKey), nil
}

func PublicationPayload(bundle PublicIdentityBundle) ([]byte, error) {
	if err := validateBundleShape(bundle); err != nil {
		return nil, err
	}

	payload := make([]byte, 0, publicationPayloadCapacity(bundle))
	payload = append(payload, publicationDomain...)
	payload = append(payload, bundle.IdentityID...)
	payload = appendUint64(payload, bundle.PublicationRevision)
	payload = appendBytes(payload, bundle.IdentityPublicKey)
	payload = appendUint32(payload, bundle.SignedPreKey.ID)
	payload = appendUint64(payload, uint64(bundle.SignedPreKey.CreatedAtUnixSeconds))
	payload = appendBytes(payload, bundle.SignedPreKey.PublicKey)
	payload = appendBytes(payload, bundle.SignedPreKey.Signature)
	payload = appendUint32(payload, uint32(len(bundle.OneTimePreKeys)))
	for _, preKey := range bundle.OneTimePreKeys {
		payload = appendUint32(payload, preKey.ID)
		payload = appendUint64(payload, uint64(preKey.CreatedAtUnixSeconds))
		payload = appendBytes(payload, preKey.PublicKey)
	}
	return payload, nil
}

func SignedPreKeyPayload(preKey SignedPreKey) ([]byte, error) {
	if preKey.ID == 0 || !validPublicKeyBytes(preKey.PublicKey) {
		return nil, fmt.Errorf("%w: signed prekey shape", ErrInvalidBundle)
	}
	payload := make([]byte, 0, len(signedPreKeyDomain)+8+len(preKey.PublicKey))
	payload = append(payload, signedPreKeyDomain...)
	payload = appendUint32(payload, preKey.ID)
	payload = appendBytes(payload, preKey.PublicKey)
	return payload, nil
}

func InvitePayload(creatorIdentityID, inviteToken []byte) ([]byte, error) {
	if len(creatorIdentityID) != IdentityIDBytes || len(inviteToken) != InviteTokenBytes {
		return nil, ErrInvalidInvite
	}
	payload := make([]byte, 0, len(inviteDomain)+IdentityIDBytes+InviteTokenBytes)
	payload = append(payload, inviteDomain...)
	payload = append(payload, creatorIdentityID...)
	payload = append(payload, inviteToken...)
	return payload, nil
}

func RedemptionPayload(creatorIdentityID, redeemerIdentityID, inviteToken []byte) ([]byte, error) {
	if len(creatorIdentityID) != IdentityIDBytes || len(redeemerIdentityID) != IdentityIDBytes || len(inviteToken) != InviteTokenBytes {
		return nil, ErrInvalidInvite
	}
	payload := make([]byte, 0, len(redeemDomain)+2*IdentityIDBytes+InviteTokenBytes)
	payload = append(payload, redeemDomain...)
	payload = append(payload, creatorIdentityID...)
	payload = append(payload, redeemerIdentityID...)
	payload = append(payload, inviteToken...)
	return payload, nil
}

func ClaimPayload(creatorIdentityID, inviteToken []byte) ([]byte, error) {
	if len(creatorIdentityID) != IdentityIDBytes || len(inviteToken) != InviteTokenBytes {
		return nil, ErrInvalidInvite
	}
	payload := make([]byte, 0, len(claimDomain)+IdentityIDBytes+InviteTokenBytes)
	payload = append(payload, claimDomain...)
	payload = append(payload, creatorIdentityID...)
	payload = append(payload, inviteToken...)
	return payload, nil
}

func InviteTokenHash(inviteToken []byte) ([sha256.Size]byte, error) {
	if len(inviteToken) != InviteTokenBytes {
		return [sha256.Size]byte{}, ErrInvalidInvite
	}
	return sha256.Sum256(inviteToken), nil
}

func validateBundleShape(bundle PublicIdentityBundle) error {
	if len(bundle.IdentityID) != IdentityIDBytes || !validPublicKeyBytes(bundle.IdentityPublicKey) || bundle.PublicationRevision == 0 {
		return ErrInvalidBundle
	}
	if bundle.SignedPreKey.ID == 0 || bundle.SignedPreKey.CreatedAtUnixSeconds < 0 || !validPublicKeyBytes(bundle.SignedPreKey.PublicKey) || !validSignature(bundle.SignedPreKey.Signature) {
		return ErrInvalidBundle
	}
	if len(bundle.PublicationSignature) > MaxSignatureBytes || len(bundle.OneTimePreKeys) > MaxOneTimePreKeys {
		return ErrInvalidBundle
	}

	var previousID uint32
	for _, preKey := range bundle.OneTimePreKeys {
		if preKey.ID == 0 || preKey.ID == bundle.SignedPreKey.ID || preKey.ID <= previousID || preKey.CreatedAtUnixSeconds < 0 || !validPublicKeyBytes(preKey.PublicKey) {
			return ErrInvalidBundle
		}
		previousID = preKey.ID
	}
	return nil
}

func validateSignedBundleShape(bundle PublicIdentityBundle) error {
	if err := validateBundleShape(bundle); err != nil {
		return err
	}
	if !validSignature(bundle.PublicationSignature) {
		return ErrInvalidBundle
	}
	return nil
}

func validateInviteShape(invite InviteDescriptor) error {
	if len(invite.CreatorIdentityID) != IdentityIDBytes || len(invite.InviteToken) != InviteTokenBytes || !validSignature(invite.InviteSignature) {
		return ErrInvalidInvite
	}
	return nil
}

func validPublicKeyBytes(value []byte) bool {
	return len(value) > 0 && len(value) <= MaxPublicKeyBytes
}

func validSignature(value []byte) bool {
	return len(value) > 0 && len(value) <= MaxSignatureBytes
}

func publicationPayloadCapacity(bundle PublicIdentityBundle) int {
	capacity := len(publicationDomain) + IdentityIDBytes + 8 + 4 + len(bundle.IdentityPublicKey) + 4 + 8 + 4 + len(bundle.SignedPreKey.PublicKey) + 4 + len(bundle.SignedPreKey.Signature) + 4
	for _, preKey := range bundle.OneTimePreKeys {
		capacity += 4 + 8 + 4 + len(preKey.PublicKey)
	}
	return capacity
}

func appendUint32(dst []byte, value uint32) []byte {
	return binary.BigEndian.AppendUint32(dst, value)
}

func appendUint64(dst []byte, value uint64) []byte {
	return binary.BigEndian.AppendUint64(dst, value)
}

func appendBytes(dst, value []byte) []byte {
	dst = appendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}
