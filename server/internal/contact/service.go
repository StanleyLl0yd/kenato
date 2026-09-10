package contact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	InviteLifetime              = 24 * time.Hour
	MaxStoredIdentities         = 100_000
	MaxStoredInvites            = 250_000
	MaxActiveInvitesPerIdentity = 16
)

var (
	ErrUnsupportedVersion  = errors.New("unsupported protocol version")
	ErrIdentityNotFound    = errors.New("identity not found")
	ErrPublicationConflict = errors.New("identity publication revision conflict")
	ErrCapacity            = errors.New("server contact-state capacity reached")
	ErrInviteNotFound      = errors.New("invite not found")
	ErrInviteExpired       = errors.New("invite expired")
	ErrInviteAlreadyUsed   = errors.New("invite already redeemed")
	ErrInviteNotRedeemed   = errors.New("invite has not been redeemed")
	ErrSelfInvite          = errors.New("self-invite is not allowed")
)

type PublicationRecord struct {
	Bundle        PublicIdentityBundle
	EncodedBundle []byte
	PayloadHash   [sha256.Size]byte
}

type StoredIdentity struct {
	EncodedBundle []byte
}

type RedeemRecord struct {
	TokenHash           [sha256.Size]byte
	CreatorIdentityID   []byte
	RedeemerPublication PublicationRecord
	RedemptionSignature []byte
	RedeemedAt          int64
}

type RedeemResult struct {
	RedeemedAt int64
}

type ClaimRecord struct {
	TokenHash         [sha256.Size]byte
	CreatorIdentityID []byte
	ClaimedAt         int64
}

type ClaimResult struct {
	RedeemerBundle      []byte
	RedemptionSignature []byte
	RedeemedAt          int64
}

type Store interface {
	PublishIdentity(context.Context, PublicationRecord) (uint64, error)
	GetIdentity(context.Context, []byte) (StoredIdentity, error)
	CreateInvite(context.Context, [sha256.Size]byte, []byte, int64, int64) (int64, error)
	RedeemInvite(context.Context, RedeemRecord) (RedeemResult, error)
	ClaimInvite(context.Context, ClaimRecord) (ClaimResult, error)
}

type Service struct {
	store Store
	clock func() time.Time
}

func NewService(store Store) *Service {
	return &Service{store: store, clock: time.Now}
}

func newServiceWithClock(store Store, clock func() time.Time) *Service {
	return &Service{store: store, clock: clock}
}

func (s *Service) PublishIdentity(ctx context.Context, request PublishIdentityRequest) (uint64, error) {
	if request.ProtocolVersion != ProtocolVersion {
		return 0, ErrUnsupportedVersion
	}
	record, err := s.publicationRecord(request.Bundle)
	if err != nil {
		return 0, err
	}
	return s.store.PublishIdentity(ctx, record)
}

func (s *Service) CreateInvite(ctx context.Context, request CreateInviteRequest) (int64, error) {
	if request.ProtocolVersion != ProtocolVersion {
		return 0, ErrUnsupportedVersion
	}
	if err := validateInviteShape(request.Invite); err != nil {
		return 0, err
	}

	creator, err := s.loadIdentity(ctx, request.Invite.CreatorIdentityID)
	if err != nil {
		return 0, err
	}
	if err := VerifyInviteDescriptor(request.Invite, creator.IdentityPublicKey); err != nil {
		return 0, err
	}
	tokenHash, err := InviteTokenHash(request.Invite.InviteToken)
	if err != nil {
		return 0, err
	}

	now, err := s.nowUnix()
	if err != nil {
		return 0, err
	}
	expiresAt := now + int64(InviteLifetime/time.Second)
	return s.store.CreateInvite(ctx, tokenHash, request.Invite.CreatorIdentityID, now, expiresAt)
}

func (s *Service) RedeemInvite(ctx context.Context, request RedeemInviteRequest) (PublicIdentityBundle, int64, error) {
	if request.ProtocolVersion != ProtocolVersion {
		return PublicIdentityBundle{}, 0, ErrUnsupportedVersion
	}
	if bytes.Equal(request.Invite.CreatorIdentityID, request.RedeemerBundle.IdentityID) {
		return PublicIdentityBundle{}, 0, ErrSelfInvite
	}
	if err := validateInviteShape(request.Invite); err != nil {
		return PublicIdentityBundle{}, 0, err
	}

	creator, err := s.loadIdentity(ctx, request.Invite.CreatorIdentityID)
	if err != nil {
		return PublicIdentityBundle{}, 0, err
	}
	if err := VerifyInviteDescriptor(request.Invite, creator.IdentityPublicKey); err != nil {
		return PublicIdentityBundle{}, 0, err
	}

	redeemerRecord, err := s.publicationRecord(request.RedeemerBundle)
	if err != nil {
		return PublicIdentityBundle{}, 0, err
	}
	if err := VerifyRedemptionProof(
		request.Invite.CreatorIdentityID,
		request.RedeemerBundle.IdentityID,
		request.Invite.InviteToken,
		request.RedemptionSignature,
		request.RedeemerBundle.IdentityPublicKey,
	); err != nil {
		return PublicIdentityBundle{}, 0, err
	}

	tokenHash, err := InviteTokenHash(request.Invite.InviteToken)
	if err != nil {
		return PublicIdentityBundle{}, 0, err
	}
	now, err := s.nowUnix()
	if err != nil {
		return PublicIdentityBundle{}, 0, err
	}
	result, err := s.store.RedeemInvite(ctx, RedeemRecord{
		TokenHash:           tokenHash,
		CreatorIdentityID:   bytes.Clone(request.Invite.CreatorIdentityID),
		RedeemerPublication: redeemerRecord,
		RedemptionSignature: bytes.Clone(request.RedemptionSignature),
		RedeemedAt:          now,
	})
	if err != nil {
		return PublicIdentityBundle{}, 0, err
	}
	return creator, result.RedeemedAt, nil
}

func (s *Service) ClaimInvite(ctx context.Context, request ClaimInviteRequest) (PublicIdentityBundle, []byte, int64, error) {
	if request.ProtocolVersion != ProtocolVersion {
		return PublicIdentityBundle{}, nil, 0, ErrUnsupportedVersion
	}
	if len(request.CreatorIdentityID) != IdentityIDBytes || len(request.InviteToken) != InviteTokenBytes || !validSignature(request.ClaimSignature) {
		return PublicIdentityBundle{}, nil, 0, ErrInvalidInvite
	}

	creator, err := s.loadIdentity(ctx, request.CreatorIdentityID)
	if err != nil {
		return PublicIdentityBundle{}, nil, 0, err
	}
	if err := VerifyClaimProof(
		request.CreatorIdentityID,
		request.InviteToken,
		request.ClaimSignature,
		creator.IdentityPublicKey,
	); err != nil {
		return PublicIdentityBundle{}, nil, 0, err
	}
	tokenHash, err := InviteTokenHash(request.InviteToken)
	if err != nil {
		return PublicIdentityBundle{}, nil, 0, err
	}
	now, err := s.nowUnix()
	if err != nil {
		return PublicIdentityBundle{}, nil, 0, err
	}

	result, err := s.store.ClaimInvite(ctx, ClaimRecord{
		TokenHash:         tokenHash,
		CreatorIdentityID: bytes.Clone(request.CreatorIdentityID),
		ClaimedAt:         now,
	})
	if err != nil {
		return PublicIdentityBundle{}, nil, 0, err
	}
	redeemer, err := decodeAndValidateStoredBundle(result.RedeemerBundle)
	if err != nil {
		return PublicIdentityBundle{}, nil, 0, fmt.Errorf("stored redeemer identity is invalid: %w", err)
	}
	if err := VerifyRedemptionProof(
		request.CreatorIdentityID,
		redeemer.IdentityID,
		request.InviteToken,
		result.RedemptionSignature,
		redeemer.IdentityPublicKey,
	); err != nil {
		return PublicIdentityBundle{}, nil, 0, fmt.Errorf("stored redemption proof is invalid: %w", err)
	}
	return redeemer, bytes.Clone(result.RedemptionSignature), result.RedeemedAt, nil
}

func (s *Service) publicationRecord(bundle PublicIdentityBundle) (PublicationRecord, error) {
	if bundle.PublicationRevision == 0 || bundle.PublicationRevision > math.MaxInt64 {
		return PublicationRecord{}, ErrInvalidBundle
	}
	if err := ValidatePublicIdentityBundle(bundle); err != nil {
		return PublicationRecord{}, err
	}
	payload, err := PublicationPayload(bundle)
	if err != nil {
		return PublicationRecord{}, err
	}
	encoded, err := EncodePublicIdentityBundle(bundle)
	if err != nil {
		return PublicationRecord{}, err
	}
	return PublicationRecord{
		Bundle:        bundle,
		EncodedBundle: encoded,
		PayloadHash:   sha256.Sum256(payload),
	}, nil
}

func (s *Service) loadIdentity(ctx context.Context, identityID []byte) (PublicIdentityBundle, error) {
	if len(identityID) != IdentityIDBytes {
		return PublicIdentityBundle{}, ErrIdentityNotFound
	}
	stored, err := s.store.GetIdentity(ctx, identityID)
	if err != nil {
		return PublicIdentityBundle{}, err
	}
	bundle, err := decodeAndValidateStoredBundle(stored.EncodedBundle)
	if err != nil {
		return PublicIdentityBundle{}, fmt.Errorf("stored identity is invalid: %w", err)
	}
	if !bytes.Equal(bundle.IdentityID, identityID) {
		return PublicIdentityBundle{}, fmt.Errorf("stored identity id mismatch: %w", ErrInvalidBundle)
	}
	return bundle, nil
}

func decodeAndValidateStoredBundle(encoded []byte) (PublicIdentityBundle, error) {
	bundle, err := DecodePublicIdentityBundle(encoded)
	if err != nil {
		return PublicIdentityBundle{}, err
	}
	if err := ValidatePublicIdentityBundle(bundle); err != nil {
		return PublicIdentityBundle{}, err
	}
	return bundle, nil
}

func (s *Service) nowUnix() (int64, error) {
	now := s.clock().UTC().Unix()
	if now < 0 || now > math.MaxInt64-int64(InviteLifetime/time.Second) {
		return 0, errors.New("contact service clock is outside the supported range")
	}
	return now, nil
}
