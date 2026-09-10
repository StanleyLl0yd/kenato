package contact

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"path/filepath"
	"testing"
	"time"
)

func TestRedeemerAccountRolloverReusesReservationAndReplacesInit(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session-rollover-init.db"))
	defer store.Close()

	now := time.Unix(2_100_400_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, creator)
	mustPublish(t, ctx, contacts, redeemer)

	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })
	creatorSession := newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 1)
	redeemerSessionV1 := newSignedSessionBundle(t, redeemer.IdentityID, redeemerKey, 1, 1, 1)
	mustPublishSession(t, ctx, sessions, creatorSession)
	mustPublishSession(t, ctx, sessions, redeemerSessionV1)

	token := establishRedeemedInvite(
		t,
		ctx,
		contacts,
		creator,
		creatorKey,
		redeemer,
		redeemerKey,
		deterministicToken(0x75),
	)
	reserved := reserveSessionForInvite(t, ctx, sessions, creator, redeemer, redeemerKey, token)

	firstSubmit := signedSessionInitRequest(
		t,
		creator.IdentityID,
		redeemer.IdentityID,
		token,
		reserved,
		redeemerSessionV1.AccountGeneration,
		[]byte("old-generation-init"),
		redeemerKey,
	)
	if err := sessions.SubmitSessionInit(ctx, firstSubmit); err != nil {
		t.Fatalf("submit initial generation init: %v", err)
	}
	assertSessionTemporaryRows(t, store, 1, 1)

	redeemerSessionV2 := newSignedSessionBundle(t, redeemer.IdentityID, redeemerKey, 2, 1, 1)
	mustPublishSession(t, ctx, sessions, redeemerSessionV2)
	assertSessionTemporaryRows(t, store, 1, 0)

	replayedReservation := reserveSessionForInvite(t, ctx, sessions, creator, redeemer, redeemerKey, token)
	if replayedReservation.CreatorOneTimeKey.ID != reserved.CreatorOneTimeKey.ID ||
		!bytes.Equal(replayedReservation.CreatorOneTimeKey.PublicKey, reserved.CreatorOneTimeKey.PublicKey) {
		t.Fatal("redeemer rollover changed the creator OTK reservation")
	}

	secondSubmit := signedSessionInitRequest(
		t,
		creator.IdentityID,
		redeemer.IdentityID,
		token,
		replayedReservation,
		redeemerSessionV2.AccountGeneration,
		[]byte("replacement-generation-init"),
		redeemerKey,
	)
	if err := sessions.SubmitSessionInit(ctx, secondSubmit); err != nil {
		t.Fatalf("submit replacement generation init: %v", err)
	}
	assertSessionTemporaryRows(t, store, 1, 1)

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
		t.Fatalf("claim replacement generation init: %v", err)
	}
	if result.RedeemerSessionBundle.AccountGeneration != 2 {
		t.Fatalf("claimed redeemer generation = %d, want 2", result.RedeemerSessionBundle.AccountGeneration)
	}
	if !bytes.Equal(result.OlmMessage, secondSubmit.OlmMessage) {
		t.Fatal("claim returned stale redeemer initialization frame")
	}
}

func signedSessionInitRequest(
	t *testing.T,
	creatorIdentityID,
	redeemerIdentityID,
	token []byte,
	reserved ReserveSessionBootstrapResult,
	redeemerGeneration uint64,
	message []byte,
	redeemerKey *ecdsa.PrivateKey,
) SubmitSessionInitRequest {
	t.Helper()
	request := SubmitSessionInitRequest{
		ProtocolVersion:           SessionProtocolVersion,
		CreatorIdentityID:         bytes.Clone(creatorIdentityID),
		RedeemerIdentityID:        bytes.Clone(redeemerIdentityID),
		InviteToken:               bytes.Clone(token),
		CreatorAccountGeneration:  reserved.CreatorBundle.AccountGeneration,
		CreatorOneTimePreKeyID:    reserved.CreatorOneTimeKey.ID,
		RedeemerAccountGeneration: redeemerGeneration,
		OlmMessageType:            OlmMessageTypePreKey,
		OlmMessage:                bytes.Clone(message),
	}
	payload, err := SessionSubmitPayload(request)
	if err != nil {
		t.Fatal(err)
	}
	request.SubmitSignature = signPayload(t, redeemerKey, payload)
	return request
}
