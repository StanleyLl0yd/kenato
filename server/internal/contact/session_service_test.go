package contact

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

type memorySessionStore struct {
	bootstraps map[string]StoredSessionBootstrap
	reserved   StoredSessionReservation
	init       *SessionInitRecord
	claim      StoredSessionClaim
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{bootstraps: make(map[string]StoredSessionBootstrap)}
}

func (s *memorySessionStore) PublishSessionBootstrap(_ context.Context, record SessionBootstrapPublicationRecord) (uint64, uint64, error) {
	s.bootstraps[string(record.Bundle.IdentityID)] = StoredSessionBootstrap{EncodedBundle: bytes.Clone(record.EncodedBundle)}
	return record.Bundle.AccountGeneration, record.Bundle.PublicationRevision, nil
}

func (s *memorySessionStore) GetSessionBootstrap(_ context.Context, identityID []byte) (StoredSessionBootstrap, error) {
	stored, ok := s.bootstraps[string(identityID)]
	if !ok {
		return StoredSessionBootstrap{}, ErrSessionKeyUnavailable
	}
	return StoredSessionBootstrap{EncodedBundle: bytes.Clone(stored.EncodedBundle)}, nil
}

func (s *memorySessionStore) ReserveSessionBootstrap(_ context.Context, _ SessionReservationRecord) (StoredSessionReservation, error) {
	if len(s.reserved.CreatorBundle) == 0 {
		return StoredSessionReservation{}, ErrSessionKeyUnavailable
	}
	return StoredSessionReservation{
		CreatorBundle: bytes.Clone(s.reserved.CreatorBundle),
		CreatorOneTimeKey: cloneSessionOneTimePreKey(s.reserved.CreatorOneTimeKey),
	}, nil
}

func (s *memorySessionStore) SubmitSessionInit(_ context.Context, record SessionInitRecord) error {
	copyRecord := record
	copyRecord.OlmMessage = bytes.Clone(record.OlmMessage)
	copyRecord.RedeemerSessionBundle = bytes.Clone(record.RedeemerSessionBundle)
	s.init = &copyRecord
	return nil
}

func (s *memorySessionStore) ClaimSessionInit(_ context.Context, _ SessionClaimRecord) (StoredSessionClaim, error) {
	if len(s.claim.OlmMessage) == 0 {
		return StoredSessionClaim{}, ErrSessionInitMissing
	}
	return s.claim, nil
}

type identityMemoryStore struct {
	bundles map[string][]byte
}

func (s *identityMemoryStore) PublishIdentity(context.Context, PublicationRecord) (uint64, error) { return 0, errors.New("unused") }
func (s *identityMemoryStore) GetIdentity(_ context.Context, identityID []byte) (StoredIdentity, error) {
	encoded, ok := s.bundles[string(identityID)]
	if !ok { return StoredIdentity{}, ErrIdentityNotFound }
	return StoredIdentity{EncodedBundle: bytes.Clone(encoded)}, nil
}
func (s *identityMemoryStore) CreateInvite(context.Context, [sha256.Size]byte, []byte, int64, int64) (int64, error) { return 0, errors.New("unused") }
func (s *identityMemoryStore) RedeemInvite(context.Context, RedeemRecord) (RedeemResult, error) { return RedeemResult{}, errors.New("unused") }
func (s *identityMemoryStore) ClaimInvite(context.Context, ClaimRecord) (ClaimResult, error) { return ClaimResult{}, errors.New("unused") }

func TestSessionServicePublishRequiresKenatoIdentityBinding(t *testing.T) {
	identityBundle, identityKey := newSignedBundle(t, 0)
	identityStore := newIdentityMemoryStore(t, identityBundle)
	sessionStore := newMemorySessionStore()
	service := newSessionServiceWithClock(identityStore, sessionStore, func() int64 { return 1000 })

	bundle := newSignedSessionBundle(t, identityBundle.IdentityID, identityKey, 1, 1, 2)
	generation, revision, err := service.PublishSessionBootstrap(context.Background(), PublishSessionBootstrapRequest{
		ProtocolVersion: SessionProtocolVersion,
		Bundle: bundle,
	})
	if err != nil { t.Fatalf("publish valid bootstrap: %v", err) }
	if generation != 1 || revision != 1 { t.Fatalf("unexpected accepted generation/revision %d/%d", generation, revision) }

	bundle.OlmCurve25519IdentityKey[0] ^= 0xff
	if _, _, err := service.PublishSessionBootstrap(context.Background(), PublishSessionBootstrapRequest{ProtocolVersion: SessionProtocolVersion, Bundle: bundle}); err == nil {
		t.Fatal("tampered engine identity accepted")
	}
}

func TestSessionServiceReserveRejectsIdentitySubstitution(t *testing.T) {
	creator, creatorKey := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	identityStore := newIdentityMemoryStore(t, creator, redeemer)
	sessionStore := newMemorySessionStore()
	creatorSession := newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 1)
	encoded, err := EncodeSessionBootstrapBundle(creatorSession)
	if err != nil { t.Fatal(err) }
	sessionStore.reserved = StoredSessionReservation{CreatorBundle: encoded, CreatorOneTimeKey: creatorSession.OneTimePreKeys[0]}
	service := newSessionServiceWithClock(identityStore, sessionStore, func() int64 { return 1000 })

	token := bytes.Repeat([]byte{0x44}, InviteTokenBytes)
	request := ReserveSessionBootstrapRequest{
		ProtocolVersion: SessionProtocolVersion,
		CreatorIdentityID: bytes.Clone(creator.IdentityID),
		RedeemerIdentityID: bytes.Clone(redeemer.IdentityID),
		InviteToken: token,
	}
	payload, _ := SessionReservePayload(request.CreatorIdentityID, request.RedeemerIdentityID, token)
	request.ReserveSignature = signPayload(t, redeemerKey, payload)
	if _, err := service.ReserveSessionBootstrap(context.Background(), request); err != nil { t.Fatalf("reserve valid bootstrap: %v", err) }

	request.RedeemerIdentityID = bytes.Clone(creator.IdentityID)
	if _, err := service.ReserveSessionBootstrap(context.Background(), request); err == nil { t.Fatal("identity substitution accepted") }
}

func TestSessionServiceSubmitBindsRedeemerGenerationAndCiphertext(t *testing.T) {
	creator, _ := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	identityStore := newIdentityMemoryStore(t, creator, redeemer)
	sessionStore := newMemorySessionStore()
	redeemerSession := newSignedSessionBundle(t, redeemer.IdentityID, redeemerKey, 7, 2, 1)
	encoded, err := EncodeSessionBootstrapBundle(redeemerSession)
	if err != nil { t.Fatal(err) }
	sessionStore.bootstraps[string(redeemer.IdentityID)] = StoredSessionBootstrap{EncodedBundle: encoded}
	service := newSessionServiceWithClock(identityStore, sessionStore, func() int64 { return 1000 })

	request := SubmitSessionInitRequest{
		ProtocolVersion: SessionProtocolVersion,
		CreatorIdentityID: bytes.Clone(creator.IdentityID),
		RedeemerIdentityID: bytes.Clone(redeemer.IdentityID),
		InviteToken: bytes.Repeat([]byte{0x55}, InviteTokenBytes),
		CreatorAccountGeneration: 3,
		CreatorOneTimePreKeyID: 9,
		RedeemerAccountGeneration: 7,
		OlmMessageType: OlmMessageTypePreKey,
		OlmMessage: []byte("opaque-pre-key-frame"),
	}
	payload, _ := SessionSubmitPayload(request)
	request.SubmitSignature = signPayload(t, redeemerKey, payload)
	if err := service.SubmitSessionInit(context.Background(), request); err != nil { t.Fatalf("submit valid init: %v", err) }
	if sessionStore.init == nil || !bytes.Equal(sessionStore.init.OlmMessage, request.OlmMessage) { t.Fatal("session init was not stored") }

	request.RedeemerAccountGeneration++
	payload, _ = SessionSubmitPayload(request)
	request.SubmitSignature = signPayload(t, redeemerKey, payload)
	if err := service.SubmitSessionInit(context.Background(), request); !errors.Is(err, ErrSessionConflict) { t.Fatalf("wrong generation error = %v", err) }
}

func newIdentityMemoryStore(t *testing.T, bundles ...PublicIdentityBundle) *identityMemoryStore {
	t.Helper()
	store := &identityMemoryStore{bundles: make(map[string][]byte)}
	for _, bundle := range bundles {
		encoded, err := EncodePublicIdentityBundle(bundle)
		if err != nil { t.Fatalf("encode identity bundle: %v", err) }
		store.bundles[string(bundle.IdentityID)] = encoded
	}
	return store
}

func newSignedSessionBundle(t *testing.T, identityID []byte, identityKey *ecdsa.PrivateKey, generation, revision uint64, oneTimeCount int) SessionBootstrapBundle {
	t.Helper()
	bundle := SessionBootstrapBundle{
		IdentityID: bytes.Clone(identityID),
		AccountGeneration: generation,
		PublicationRevision: revision,
		OlmEd25519IdentityKey: bytes.Repeat([]byte{0x11}, OlmPublicKeyBytes),
		OlmCurve25519IdentityKey: bytes.Repeat([]byte{0x22}, OlmPublicKeyBytes),
	}
	for i := 0; i < oneTimeCount; i++ {
		key := bytes.Repeat([]byte{byte(0x30 + i)}, OlmPublicKeyBytes)
		bundle.OneTimePreKeys = append(bundle.OneTimePreKeys, SessionOneTimePreKey{ID: uint64(i + 1), PublicKey: key})
	}
	payload, err := SessionBootstrapPayload(bundle)
	if err != nil { t.Fatalf("session bootstrap payload: %v", err) }
	bundle.BindingSignature = signPayload(t, identityKey, payload)
	return bundle
}

func TestSessionCanonicalBindingSignatureUsesSHA256ECDSA(t *testing.T) {
	identity, key := newSignedBundle(t, 0)
	bundle := newSignedSessionBundle(t, identity.IdentityID, key, 1, 1, 1)
	payload, err := SessionBootstrapPayload(bundle)
	if err != nil { t.Fatal(err) }
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], bundle.BindingSignature) { t.Fatal("binding signature does not verify") }

	bad := bytes.Clone(bundle.BindingSignature)
	if len(bad) == 0 { t.Fatal("empty test signature") }
	bad[len(bad)-1] ^= 1
	if ecdsa.VerifyASN1(&key.PublicKey, digest[:], bad) { t.Fatal("tampered signature verifies") }
}

func TestSessionBootstrapRejectsNonCanonicalKeyOrdering(t *testing.T) {
	identity, key := newSignedBundle(t, 0)
	bundle := newSignedSessionBundle(t, identity.IdentityID, key, 1, 1, 2)
	bundle.OneTimePreKeys[1].PublicKey = bytes.Clone(bundle.OneTimePreKeys[0].PublicKey)
	if _, err := SessionBootstrapPayload(bundle); err == nil { t.Fatal("duplicate/non-increasing key ordering accepted") }
}

func TestSessionSubmitProofRejectsCiphertextTamper(t *testing.T) {
	creator, _ := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	request := SubmitSessionInitRequest{
		ProtocolVersion: SessionProtocolVersion,
		CreatorIdentityID: creator.IdentityID,
		RedeemerIdentityID: redeemer.IdentityID,
		InviteToken: bytes.Repeat([]byte{7}, InviteTokenBytes),
		CreatorAccountGeneration: 1,
		CreatorOneTimePreKeyID: 1,
		RedeemerAccountGeneration: 1,
		OlmMessageType: OlmMessageTypePreKey,
		OlmMessage: []byte("ciphertext"),
	}
	payload, _ := SessionSubmitPayload(request)
	request.SubmitSignature = signPayload(t, redeemerKey, payload)
	if err := VerifySessionSubmitProof(request, redeemer.IdentityPublicKey); err != nil { t.Fatalf("valid proof rejected: %v", err) }
	request.OlmMessage[0] ^= 1
	if err := VerifySessionSubmitProof(request, redeemer.IdentityPublicKey); err == nil { t.Fatal("tampered ciphertext accepted") }
}

func init() {
	_, _ = rand.Read(nil)
}
