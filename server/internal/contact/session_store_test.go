package contact

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteSessionBootstrapLifecycle(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session.db"))
	defer store.Close()

	now := time.Unix(2_100_000_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, creator)
	mustPublish(t, ctx, contacts, redeemer)

	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })
	creatorSession := newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 2)
	redeemerSession := newSignedSessionBundle(t, redeemer.IdentityID, redeemerKey, 1, 1, 2)
	mustPublishSession(t, ctx, sessions, creatorSession)
	mustPublishSession(t, ctx, sessions, redeemerSession)

	token := deterministicToken(0x21)
	invite := signedInvite(t, creator, creatorKey, token)
	if _, err := contacts.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite}); err != nil {
		t.Fatalf("create invite: %v", err)
	}
	redemptionProof := signedRedemption(t, creator.IdentityID, redeemer, redeemerKey, token)
	if _, _, err := contacts.RedeemInvite(ctx, RedeemInviteRequest{
		ProtocolVersion:     ProtocolVersion,
		Invite:              invite,
		RedeemerBundle:      redeemer,
		RedemptionSignature: redemptionProof,
	}); err != nil {
		t.Fatalf("redeem invite: %v", err)
	}

	reserve := ReserveSessionBootstrapRequest{
		ProtocolVersion:    SessionProtocolVersion,
		CreatorIdentityID:  bytes.Clone(creator.IdentityID),
		RedeemerIdentityID: bytes.Clone(redeemer.IdentityID),
		InviteToken:        bytes.Clone(token),
	}
	reservePayload, err := SessionReservePayload(reserve.CreatorIdentityID, reserve.RedeemerIdentityID, reserve.InviteToken)
	if err != nil {
		t.Fatal(err)
	}
	reserve.ReserveSignature = signPayload(t, redeemerKey, reservePayload)
	reserved, err := sessions.ReserveSessionBootstrap(ctx, reserve)
	if err != nil {
		t.Fatalf("reserve creator prekey: %v", err)
	}
	if reserved.CreatorOneTimeKey.ID != creatorSession.OneTimePreKeys[0].ID ||
		!bytes.Equal(reserved.CreatorOneTimeKey.PublicKey, creatorSession.OneTimePreKeys[0].PublicKey) {
		t.Fatal("unexpected creator prekey reservation")
	}

	retry, err := sessions.ReserveSessionBootstrap(ctx, reserve)
	if err != nil {
		t.Fatalf("idempotent reserve: %v", err)
	}
	if retry.CreatorOneTimeKey.ID != reserved.CreatorOneTimeKey.ID || !bytes.Equal(retry.CreatorOneTimeKey.PublicKey, reserved.CreatorOneTimeKey.PublicKey) {
		t.Fatal("reservation replay returned a different one-time key")
	}

	submit := SubmitSessionInitRequest{
		ProtocolVersion:           SessionProtocolVersion,
		CreatorIdentityID:         bytes.Clone(creator.IdentityID),
		RedeemerIdentityID:        bytes.Clone(redeemer.IdentityID),
		InviteToken:               bytes.Clone(token),
		CreatorAccountGeneration:  reserved.CreatorBundle.AccountGeneration,
		CreatorOneTimePreKeyID:    reserved.CreatorOneTimeKey.ID,
		RedeemerAccountGeneration: redeemerSession.AccountGeneration,
		OlmMessageType:            OlmMessageTypePreKey,
		OlmMessage:                []byte("opaque-olm-pre-key-frame"),
	}
	submitPayload, err := SessionSubmitPayload(submit)
	if err != nil {
		t.Fatal(err)
	}
	submit.SubmitSignature = signPayload(t, redeemerKey, submitPayload)
	if err := sessions.SubmitSessionInit(ctx, submit); err != nil {
		t.Fatalf("submit session init: %v", err)
	}
	if err := sessions.SubmitSessionInit(ctx, submit); err != nil {
		t.Fatalf("idempotent submit session init: %v", err)
	}

	mutated := submit
	mutated.OlmMessage = []byte("different-opaque-frame")
	mutatedPayload, err := SessionSubmitPayload(mutated)
	if err != nil {
		t.Fatal(err)
	}
	mutated.SubmitSignature = signPayload(t, redeemerKey, mutatedPayload)
	if err := sessions.SubmitSessionInit(ctx, mutated); !errors.Is(err, ErrSessionInitConflict) {
		t.Fatalf("conflicting session init error = %v", err)
	}

	claim := ClaimSessionInitRequest{
		ProtocolVersion:   SessionProtocolVersion,
		CreatorIdentityID: bytes.Clone(creator.IdentityID),
		InviteToken:       bytes.Clone(token),
	}
	claimPayload, err := SessionClaimPayload(claim.CreatorIdentityID, claim.InviteToken)
	if err != nil {
		t.Fatal(err)
	}
	claim.ClaimSignature = signPayload(t, creatorKey, claimPayload)
	result, err := sessions.ClaimSessionInit(ctx, claim)
	if err != nil {
		t.Fatalf("claim session init: %v", err)
	}
	if !bytes.Equal(result.RedeemerIdentityBundle.IdentityID, redeemer.IdentityID) ||
		!bytes.Equal(result.RedemptionSignature, redemptionProof) ||
		!bytes.Equal(result.OlmMessage, submit.OlmMessage) ||
		!bytes.Equal(result.SubmitSignature, submit.SubmitSignature) ||
		result.CreatorAccountGeneration != creatorSession.AccountGeneration ||
		result.CreatorOneTimeKey.ID != reserved.CreatorOneTimeKey.ID {
		t.Fatal("unexpected session claim result")
	}

	if _, err := sessions.ClaimSessionInit(ctx, claim); !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("claimed session relationship was retained: %v", err)
	}
	assertSessionTemporaryRows(t, store, 0, 0)
}

func TestSQLiteSessionReservationConsumesDistinctKeysAndExhausts(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session.db"))
	defer store.Close()

	now := time.Unix(2_100_000_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	firstRedeemer, firstKey := newSignedBundle(t, 0)
	secondRedeemer, secondKey := newSignedBundle(t, 0)
	thirdRedeemer, thirdKey := newSignedBundle(t, 0)
	for _, identity := range []PublicIdentityBundle{creator, firstRedeemer, secondRedeemer, thirdRedeemer} {
		mustPublish(t, ctx, contacts, identity)
	}

	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })
	creatorSession := newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 2)
	mustPublishSession(t, ctx, sessions, creatorSession)

	first := establishRedeemedInvite(t, ctx, contacts, creator, creatorKey, firstRedeemer, firstKey, deterministicToken(0x31))
	second := establishRedeemedInvite(t, ctx, contacts, creator, creatorKey, secondRedeemer, secondKey, deterministicToken(0x41))
	third := establishRedeemedInvite(t, ctx, contacts, creator, creatorKey, thirdRedeemer, thirdKey, deterministicToken(0x51))

	firstReservation := reserveSessionForInvite(t, ctx, sessions, creator, firstRedeemer, firstKey, first)
	secondReservation := reserveSessionForInvite(t, ctx, sessions, creator, secondRedeemer, secondKey, second)
	if firstReservation.CreatorOneTimeKey.ID == secondReservation.CreatorOneTimeKey.ID {
		t.Fatal("two invites received the same creator one-time key")
	}

	thirdRequest := ReserveSessionBootstrapRequest{
		ProtocolVersion:    SessionProtocolVersion,
		CreatorIdentityID:  creator.IdentityID,
		RedeemerIdentityID: thirdRedeemer.IdentityID,
		InviteToken:        third,
	}
	payload, err := SessionReservePayload(thirdRequest.CreatorIdentityID, thirdRequest.RedeemerIdentityID, thirdRequest.InviteToken)
	if err != nil {
		t.Fatal(err)
	}
	thirdRequest.ReserveSignature = signPayload(t, thirdKey, payload)
	if _, err := sessions.ReserveSessionBootstrap(ctx, thirdRequest); !errors.Is(err, ErrSessionKeyUnavailable) {
		t.Fatalf("exhausted prekey pool error = %v", err)
	}
}

func TestSQLiteSessionPublicationIsMonotonicAndDoesNotResurrectConsumedKey(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session.db"))
	defer store.Close()

	now := time.Unix(2_100_000_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, creator)
	mustPublish(t, ctx, contacts, redeemer)
	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })

	first := newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 2)
	mustPublishSession(t, ctx, sessions, first)
	if generation, revision, err := sessions.PublishSessionBootstrap(ctx, PublishSessionBootstrapRequest{ProtocolVersion: SessionProtocolVersion, Bundle: first}); err != nil || generation != 1 || revision != 1 {
		t.Fatalf("idempotent publication: %d/%d err=%v", generation, revision, err)
	}

	token := establishRedeemedInvite(t, ctx, contacts, creator, creatorKey, redeemer, redeemerKey, deterministicToken(0x61))
	reserved := reserveSessionForInvite(t, ctx, sessions, creator, redeemer, redeemerKey, token)

	replayConsumed := cloneSessionBundle(first)
	replayConsumed.PublicationRevision = 2
	resignSessionBundle(t, &replayConsumed, creatorKey)
	if _, _, err := sessions.PublishSessionBootstrap(ctx, PublishSessionBootstrapRequest{ProtocolVersion: SessionProtocolVersion, Bundle: replayConsumed}); err != nil {
		t.Fatalf("publication retaining signed reserved key should remain valid: %v", err)
	}

	thirdKey := bytes.Repeat([]byte{0x72}, OlmPublicKeyBytes)
	replenished := cloneSessionBundle(replayConsumed)
	replenished.PublicationRevision = 3
	replenished.OneTimePreKeys = append(replenished.OneTimePreKeys, SessionOneTimePreKey{ID: 3, PublicKey: thirdKey})
	resignSessionBundle(t, &replenished, creatorKey)
	mustPublishSession(t, ctx, sessions, replenished)

	if reserved.CreatorOneTimeKey.ID != first.OneTimePreKeys[0].ID {
		t.Fatal("unexpected reservation key")
	}

	retired := cloneSessionBundle(replenished)
	retired.PublicationRevision = 4
	retired.OneTimePreKeys = []SessionOneTimePreKey{{ID: 3, PublicKey: bytes.Clone(thirdKey)}}
	resignSessionBundle(t, &retired, creatorKey)
	mustPublishSession(t, ctx, sessions, retired)

	resurrect := cloneSessionBundle(retired)
	resurrect.PublicationRevision = 5
	resurrect.OneTimePreKeys = []SessionOneTimePreKey{
		{ID: 2, PublicKey: bytes.Clone(first.OneTimePreKeys[1].PublicKey)},
		{ID: 3, PublicKey: bytes.Clone(thirdKey)},
	}
	resignSessionBundle(t, &resurrect, creatorKey)
	if _, _, err := sessions.PublishSessionBootstrap(ctx, PublishSessionBootstrapRequest{ProtocolVersion: SessionProtocolVersion, Bundle: resurrect}); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("retired key resurrection error = %v", err)
	}
}

func TestSQLiteSessionAccountGenerationMustAdvanceExactlyOne(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session.db"))
	defer store.Close()

	now := time.Unix(2_100_000_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	identity, identityKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, identity)
	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })
	mustPublishSession(t, ctx, sessions, newSignedSessionBundle(t, identity.IdentityID, identityKey, 1, 1, 1))

	skipped := newSignedSessionBundle(t, identity.IdentityID, identityKey, 3, 1, 1)
	if _, _, err := sessions.PublishSessionBootstrap(ctx, PublishSessionBootstrapRequest{ProtocolVersion: SessionProtocolVersion, Bundle: skipped}); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("skipped generation error = %v", err)
	}
	badRevision := newSignedSessionBundle(t, identity.IdentityID, identityKey, 2, 2, 1)
	if _, _, err := sessions.PublishSessionBootstrap(ctx, PublishSessionBootstrapRequest{ProtocolVersion: SessionProtocolVersion, Bundle: badRevision}); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("new generation non-one revision error = %v", err)
	}
	mustPublishSession(t, ctx, sessions, newSignedSessionBundle(t, identity.IdentityID, identityKey, 2, 1, 1))
}

func mustPublishSession(t *testing.T, ctx context.Context, service *SessionService, bundle SessionBootstrapBundle) {
	t.Helper()
	generation, revision, err := service.PublishSessionBootstrap(ctx, PublishSessionBootstrapRequest{
		ProtocolVersion: SessionProtocolVersion,
		Bundle:          bundle,
	})
	if err != nil {
		t.Fatalf("publish session bootstrap: %v", err)
	}
	if generation != bundle.AccountGeneration || revision != bundle.PublicationRevision {
		t.Fatalf("unexpected accepted session publication %d/%d", generation, revision)
	}
}

func establishRedeemedInvite(
	t *testing.T,
	ctx context.Context,
	service *Service,
	creator PublicIdentityBundle,
	creatorKey interface{ Public() any },
	redeemer PublicIdentityBundle,
	redeemerKey interface{ Public() any },
	token []byte,
) []byte {
	t.Helper()
	creatorPrivateKey, ok := creatorKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("unexpected creator key type")
	}
	redeemerPrivateKey, ok := redeemerKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("unexpected redeemer key type")
	}
	invite := signedInvite(t, creator, creatorPrivateKey, token)
	if _, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite}); err != nil {
		t.Fatalf("create invite: %v", err)
	}
	proof := signedRedemption(t, creator.IdentityID, redeemer, redeemerPrivateKey, token)
	if _, _, err := service.RedeemInvite(ctx, RedeemInviteRequest{
		ProtocolVersion:     ProtocolVersion,
		Invite:              invite,
		RedeemerBundle:      redeemer,
		RedemptionSignature: proof,
	}); err != nil {
		t.Fatalf("redeem invite: %v", err)
	}
	return bytes.Clone(token)
}

func reserveSessionForInvite(
	t *testing.T,
	ctx context.Context,
	service *SessionService,
	creator PublicIdentityBundle,
	redeemer PublicIdentityBundle,
	redeemerKey *ecdsa.PrivateKey,
	token []byte,
) ReserveSessionBootstrapResult {
	t.Helper()
	request := ReserveSessionBootstrapRequest{
		ProtocolVersion:    SessionProtocolVersion,
		CreatorIdentityID:  bytes.Clone(creator.IdentityID),
		RedeemerIdentityID: bytes.Clone(redeemer.IdentityID),
		InviteToken:        bytes.Clone(token),
	}
	payload, err := SessionReservePayload(request.CreatorIdentityID, request.RedeemerIdentityID, request.InviteToken)
	if err != nil {
		t.Fatal(err)
	}
	request.ReserveSignature = signPayload(t, redeemerKey, payload)
	result, err := service.ReserveSessionBootstrap(ctx, request)
	if err != nil {
		t.Fatalf("reserve session bootstrap: %v", err)
	}
	return result
}

func resignSessionBundle(t *testing.T, bundle *SessionBootstrapBundle, identityKey *ecdsa.PrivateKey) {
	t.Helper()
	bundle.BindingSignature = nil
	payload, err := SessionBootstrapPayload(*bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.BindingSignature = signPayload(t, identityKey, payload)
}

func assertSessionTemporaryRows(t *testing.T, store *SQLiteStore, reservations, inits int) {
	t.Helper()
	var actualReservations int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM session_reservations").Scan(&actualReservations); err != nil {
		t.Fatal(err)
	}
	var actualInits int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM session_inits").Scan(&actualInits); err != nil {
		t.Fatal(err)
	}
	if actualReservations != reservations || actualInits != inits {
		t.Fatalf("temporary session rows = %d/%d, want %d/%d", actualReservations, actualInits, reservations, inits)
	}
}
