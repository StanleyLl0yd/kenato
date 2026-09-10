package contact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"time"
)

type SessionStore interface {
	PublishSessionBootstrap(context.Context, SessionBootstrapPublicationRecord) (uint64, uint64, error)
	GetSessionBootstrap(context.Context, []byte) (StoredSessionBootstrap, error)
	ReserveSessionBootstrap(context.Context, SessionReservationRecord) (StoredSessionReservation, error)
	SubmitSessionInit(context.Context, SessionInitRecord) error
	ClaimSessionInit(context.Context, SessionClaimRecord) (StoredSessionClaim, error)
}

type SessionService struct {
	identityStore Store
	sessionStore  SessionStore
	clock         func() int64
}

func NewSessionService(identityStore Store, sessionStore SessionStore) *SessionService {
	return &SessionService{
		identityStore: identityStore,
		sessionStore:  sessionStore,
		clock:         func() int64 { return time.Now().UTC().Unix() },
	}
}

func newSessionServiceWithClock(identityStore Store, sessionStore SessionStore, clock func() int64) *SessionService {
	return &SessionService{identityStore: identityStore, sessionStore: sessionStore, clock: clock}
}

func (s *SessionService) PublishSessionBootstrap(ctx context.Context, request PublishSessionBootstrapRequest) (uint64, uint64, error) {
	if request.ProtocolVersion != SessionProtocolVersion {
		return 0, 0, ErrUnsupportedVersion
	}
	identity, err := s.loadIdentity(ctx, request.Bundle.IdentityID)
	if err != nil {
		return 0, 0, err
	}
	if err := ValidateSessionBootstrapBundle(request.Bundle, identity.IdentityPublicKey); err != nil {
		return 0, 0, err
	}
	encoded, err := EncodeSessionBootstrapBundle(request.Bundle)
	if err != nil {
		return 0, 0, err
	}
	payload, err := SessionBootstrapPayload(request.Bundle)
	if err != nil {
		return 0, 0, err
	}
	return s.sessionStore.PublishSessionBootstrap(ctx, SessionBootstrapPublicationRecord{
		Bundle:        cloneSessionBundle(request.Bundle),
		EncodedBundle: encoded,
		PayloadHash:   sha256.Sum256(payload),
	})
}

func (s *SessionService) ReserveSessionBootstrap(ctx context.Context, request ReserveSessionBootstrapRequest) (ReserveSessionBootstrapResult, error) {
	if request.ProtocolVersion != SessionProtocolVersion {
		return ReserveSessionBootstrapResult{}, ErrUnsupportedVersion
	}
	if _, err := SessionReservePayload(request.CreatorIdentityID, request.RedeemerIdentityID, request.InviteToken); err != nil {
		return ReserveSessionBootstrapResult{}, err
	}
	redeemerIdentity, err := s.loadIdentity(ctx, request.RedeemerIdentityID)
	if err != nil {
		return ReserveSessionBootstrapResult{}, err
	}
	if err := VerifySessionReserveProof(request, redeemerIdentity.IdentityPublicKey); err != nil {
		return ReserveSessionBootstrapResult{}, err
	}
	tokenHash, err := InviteTokenHash(request.InviteToken)
	if err != nil {
		return ReserveSessionBootstrapResult{}, err
	}
	now, err := s.nowUnix()
	if err != nil {
		return ReserveSessionBootstrapResult{}, err
	}
	stored, err := s.sessionStore.ReserveSessionBootstrap(ctx, SessionReservationRecord{
		TokenHash:          tokenHash,
		CreatorIdentityID:  bytes.Clone(request.CreatorIdentityID),
		RedeemerIdentityID: bytes.Clone(request.RedeemerIdentityID),
		ReservedAt:         now,
	})
	if err != nil {
		return ReserveSessionBootstrapResult{}, err
	}
	bundle, err := DecodeSessionBootstrapBundle(stored.CreatorBundle)
	if err != nil {
		return ReserveSessionBootstrapResult{}, fmt.Errorf("stored creator session bootstrap is invalid: %w", err)
	}
	creatorIdentity, err := s.loadIdentity(ctx, request.CreatorIdentityID)
	if err != nil {
		return ReserveSessionBootstrapResult{}, err
	}
	if err := ValidateSessionBootstrapBundle(bundle, creatorIdentity.IdentityPublicKey); err != nil {
		return ReserveSessionBootstrapResult{}, fmt.Errorf("stored creator session bootstrap is invalid: %w", err)
	}
	if stored.CreatorOneTimeKey.ID == 0 || len(stored.CreatorOneTimeKey.PublicKey) != OlmPublicKeyBytes {
		return ReserveSessionBootstrapResult{}, fmt.Errorf("stored creator one-time key is invalid: %w", ErrInvalidSessionBootstrap)
	}
	return ReserveSessionBootstrapResult{
		CreatorBundle:     bundle,
		CreatorOneTimeKey: cloneSessionOneTimePreKey(stored.CreatorOneTimeKey),
	}, nil
}

func (s *SessionService) SubmitSessionInit(ctx context.Context, request SubmitSessionInitRequest) error {
	if request.ProtocolVersion != SessionProtocolVersion {
		return ErrUnsupportedVersion
	}
	if err := validateSessionInitShape(request); err != nil {
		return err
	}
	redeemerIdentity, err := s.loadIdentity(ctx, request.RedeemerIdentityID)
	if err != nil {
		return err
	}
	if err := VerifySessionSubmitProof(request, redeemerIdentity.IdentityPublicKey); err != nil {
		return err
	}
	redeemerBootstrap, err := s.sessionStore.GetSessionBootstrap(ctx, request.RedeemerIdentityID)
	if err != nil {
		return err
	}
	decoded, err := DecodeSessionBootstrapBundle(redeemerBootstrap.EncodedBundle)
	if err != nil {
		return fmt.Errorf("stored redeemer session bootstrap is invalid: %w", err)
	}
	if decoded.AccountGeneration != request.RedeemerAccountGeneration {
		return ErrSessionConflict
	}
	if err := ValidateSessionBootstrapBundle(decoded, redeemerIdentity.IdentityPublicKey); err != nil {
		return fmt.Errorf("stored redeemer session bootstrap is invalid: %w", err)
	}
	tokenHash, err := InviteTokenHash(request.InviteToken)
	if err != nil {
		return err
	}
	now, err := s.nowUnix()
	if err != nil {
		return err
	}
	return s.sessionStore.SubmitSessionInit(ctx, SessionInitRecord{
		TokenHash:                  tokenHash,
		CreatorIdentityID:          bytes.Clone(request.CreatorIdentityID),
		RedeemerIdentityID:         bytes.Clone(request.RedeemerIdentityID),
		CreatorAccountGeneration:   request.CreatorAccountGeneration,
		CreatorOneTimePreKeyID:     request.CreatorOneTimePreKeyID,
		RedeemerAccountGeneration:  request.RedeemerAccountGeneration,
		OlmMessageType:             request.OlmMessageType,
		OlmMessage:                 bytes.Clone(request.OlmMessage),
		SubmitSignature:            bytes.Clone(request.SubmitSignature),
		RedeemerSessionBundle:      bytes.Clone(redeemerBootstrap.EncodedBundle),
		SubmittedAt:                now,
	})
}

func (s *SessionService) ClaimSessionInit(ctx context.Context, request ClaimSessionInitRequest) (ClaimSessionInitResult, error) {
	if request.ProtocolVersion != SessionProtocolVersion {
		return ClaimSessionInitResult{}, ErrUnsupportedVersion
	}
	creatorIdentity, err := s.loadIdentity(ctx, request.CreatorIdentityID)
	if err != nil {
		return ClaimSessionInitResult{}, err
	}
	if err := VerifySessionClaimProof(request, creatorIdentity.IdentityPublicKey); err != nil {
		return ClaimSessionInitResult{}, err
	}
	tokenHash, err := InviteTokenHash(request.InviteToken)
	if err != nil {
		return ClaimSessionInitResult{}, err
	}
	now, err := s.nowUnix()
	if err != nil {
		return ClaimSessionInitResult{}, err
	}
	stored, err := s.sessionStore.ClaimSessionInit(ctx, SessionClaimRecord{
		TokenHash:         tokenHash,
		CreatorIdentityID: bytes.Clone(request.CreatorIdentityID),
		ClaimedAt:         now,
	})
	if err != nil {
		return ClaimSessionInitResult{}, err
	}
	redeemerIdentity, err := decodeAndValidateStoredBundle(stored.RedeemerIdentityBundle)
	if err != nil {
		return ClaimSessionInitResult{}, fmt.Errorf("stored redeemer identity is invalid: %w", err)
	}
	if err := VerifyRedemptionProof(
		request.CreatorIdentityID,
		redeemerIdentity.IdentityID,
		request.InviteToken,
		stored.RedemptionSignature,
		redeemerIdentity.IdentityPublicKey,
	); err != nil {
		return ClaimSessionInitResult{}, fmt.Errorf("stored redemption proof is invalid: %w", err)
	}
	redeemerSession, err := DecodeSessionBootstrapBundle(stored.RedeemerSessionBundle)
	if err != nil {
		return ClaimSessionInitResult{}, fmt.Errorf("stored redeemer session bootstrap is invalid: %w", err)
	}
	if err := ValidateSessionBootstrapBundle(redeemerSession, redeemerIdentity.IdentityPublicKey); err != nil {
		return ClaimSessionInitResult{}, fmt.Errorf("stored redeemer session bootstrap is invalid: %w", err)
	}
	if stored.CreatorOneTimeKey.ID == 0 || len(stored.CreatorOneTimeKey.PublicKey) != OlmPublicKeyBytes || stored.OlmMessageType != OlmMessageTypePreKey || len(stored.OlmMessage) == 0 || len(stored.OlmMessage) > MaxSessionCiphertextBytes {
		return ClaimSessionInitResult{}, fmt.Errorf("stored session initialization is invalid: %w", ErrInvalidSessionBootstrap)
	}
	return ClaimSessionInitResult{
		RedeemerIdentityBundle: redeemerIdentity,
		RedemptionSignature:    bytes.Clone(stored.RedemptionSignature),
		RedeemedAt:             stored.RedeemedAt,
		RedeemerSessionBundle:  redeemerSession,
		CreatorOneTimeKey:      cloneSessionOneTimePreKey(stored.CreatorOneTimeKey),
		OlmMessageType:         stored.OlmMessageType,
		OlmMessage:             bytes.Clone(stored.OlmMessage),
	}, nil
}

func (s *SessionService) loadIdentity(ctx context.Context, identityID []byte) (PublicIdentityBundle, error) {
	if len(identityID) != IdentityIDBytes {
		return PublicIdentityBundle{}, ErrIdentityNotFound
	}
	stored, err := s.identityStore.GetIdentity(ctx, identityID)
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

func (s *SessionService) nowUnix() (int64, error) {
	now := s.clock()
	if now < 0 || now > math.MaxInt64-int64(InviteLifetime/time.Second) {
		return 0, fmt.Errorf("session service clock is outside the supported range")
	}
	return now, nil
}

func cloneSessionBundle(bundle SessionBootstrapBundle) SessionBootstrapBundle {
	copyBundle := bundle
	copyBundle.IdentityID = bytes.Clone(bundle.IdentityID)
	copyBundle.OlmEd25519IdentityKey = bytes.Clone(bundle.OlmEd25519IdentityKey)
	copyBundle.OlmCurve25519IdentityKey = bytes.Clone(bundle.OlmCurve25519IdentityKey)
	copyBundle.BindingSignature = bytes.Clone(bundle.BindingSignature)
	copyBundle.OneTimePreKeys = make([]SessionOneTimePreKey, len(bundle.OneTimePreKeys))
	for i, key := range bundle.OneTimePreKeys {
		copyBundle.OneTimePreKeys[i] = cloneSessionOneTimePreKey(key)
	}
	return copyBundle
}

func cloneSessionOneTimePreKey(key SessionOneTimePreKey) SessionOneTimePreKey {
	return SessionOneTimePreKey{ID: key.ID, PublicKey: bytes.Clone(key.PublicKey)}
}
