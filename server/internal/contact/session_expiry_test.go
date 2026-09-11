package contact

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteSessionInitFailsAtInviteExpiryAndRetentionCascades(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session-expiry.db"))
	defer store.Close()

	now := time.Unix(2_100_000_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, creator)
	mustPublish(t, ctx, contacts, redeemer)

	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })
	creatorSession := newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 1)
	redeemerSession := newSignedSessionBundle(t, redeemer.IdentityID, redeemerKey, 1, 1, 1)
	mustPublishSession(t, ctx, sessions, creatorSession)
	mustPublishSession(t, ctx, sessions, redeemerSession)

	token := establishRedeemedInvite(t, ctx, contacts, creator, creatorKey, redeemer, redeemerKey, deterministicToken(0x71))
	reserved := reserveSessionForInvite(t, ctx, sessions, creator, redeemer, redeemerKey, token)
	assertSessionTemporaryRows(t, store, 1, 0)

	now = now.Add(InviteLifetime)
	submit := SubmitSessionInitRequest{
		ProtocolVersion:           SessionProtocolVersion,
		CreatorIdentityID:         bytes.Clone(creator.IdentityID),
		RedeemerIdentityID:        bytes.Clone(redeemer.IdentityID),
		InviteToken:               bytes.Clone(token),
		CreatorAccountGeneration:  reserved.CreatorBundle.AccountGeneration,
		CreatorOneTimePreKeyID:    reserved.CreatorOneTimeKey.ID,
		RedeemerAccountGeneration: redeemerSession.AccountGeneration,
		OlmMessageType:            OlmMessageTypePreKey,
		OlmMessage:                []byte("opaque-expired-frame"),
	}
	payload, err := SessionSubmitPayload(submit)
	if err != nil {
		t.Fatal(err)
	}
	submit.SubmitSignature = signPayload(t, redeemerKey, payload)
	if err := sessions.SubmitSessionInit(ctx, submit); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("submit at expiry boundary error=%v", err)
	}

	removed, err := store.PruneExpiredInvites(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("expired invites removed=%d, want 1", removed)
	}
	assertSessionTemporaryRows(t, store, 0, 0)
}

func TestSQLiteSessionReserveFailsAtInviteExpiryWithoutConsumingKey(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session-expiry.db"))
	defer store.Close()

	now := time.Unix(2_100_100_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, creator)
	mustPublish(t, ctx, contacts, redeemer)
	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })
	mustPublishSession(t, ctx, sessions, newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 1))

	token := establishRedeemedInvite(t, ctx, contacts, creator, creatorKey, redeemer, redeemerKey, deterministicToken(0x72))
	now = now.Add(InviteLifetime)

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
	if _, err := sessions.ReserveSessionBootstrap(ctx, request); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("reserve at expiry boundary error=%v", err)
	}

	var available int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM session_one_time_prekeys WHERE identity_id = ?", creator.IdentityID).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if available != 1 {
		t.Fatalf("available OTK count=%d, want 1", available)
	}
	assertSessionTemporaryRows(t, store, 0, 0)
}
