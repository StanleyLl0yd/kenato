package contact

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRedeemerAccountRolloverDoesNotConsumeAnotherCreatorOTK(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session-rollover.db"))
	defer store.Close()

	now := time.Unix(2_100_200_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, creator)
	mustPublish(t, ctx, contacts, redeemer)

	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })
	creatorSession := newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 2)
	mustPublishSession(t, ctx, sessions, creatorSession)
	mustPublishSession(t, ctx, sessions, newSignedSessionBundle(t, redeemer.IdentityID, redeemerKey, 1, 1, 1))

	token := establishRedeemedInvite(t, ctx, contacts, creator, creatorKey, redeemer, redeemerKey, deterministicToken(0x73))
	first := reserveSessionForInvite(t, ctx, sessions, creator, redeemer, redeemerKey, token)

	mustPublishSession(t, ctx, sessions, newSignedSessionBundle(t, redeemer.IdentityID, redeemerKey, 2, 1, 1))
	second := reserveSessionForInvite(t, ctx, sessions, creator, redeemer, redeemerKey, token)
	if second.CreatorOneTimeKey.ID != first.CreatorOneTimeKey.ID || !bytes.Equal(second.CreatorOneTimeKey.PublicKey, first.CreatorOneTimeKey.PublicKey) {
		t.Fatal("redeemer account rollover changed an existing creator OTK reservation")
	}

	var available int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM session_one_time_prekeys WHERE identity_id = ?", creator.IdentityID).Scan(&available); err != nil {
		t.Fatal(err)
	}
	if available != 1 {
		t.Fatalf("available creator OTK count=%d, want 1", available)
	}
}

func TestCreatorAccountRolloverInvalidatesOldReservation(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session-rollover.db"))
	defer store.Close()

	now := time.Unix(2_100_300_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	redeemer, redeemerKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, creator)
	mustPublish(t, ctx, contacts, redeemer)

	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })
	mustPublishSession(t, ctx, sessions, newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 1))

	token := establishRedeemedInvite(t, ctx, contacts, creator, creatorKey, redeemer, redeemerKey, deterministicToken(0x74))
	first := reserveSessionForInvite(t, ctx, sessions, creator, redeemer, redeemerKey, token)
	if first.CreatorBundle.AccountGeneration != 1 {
		t.Fatalf("initial creator generation=%d", first.CreatorBundle.AccountGeneration)
	}

	mustPublishSession(t, ctx, sessions, newSignedSessionBundle(t, creator.IdentityID, creatorKey, 2, 1, 1))
	second := reserveSessionForInvite(t, ctx, sessions, creator, redeemer, redeemerKey, token)
	if second.CreatorBundle.AccountGeneration != 2 {
		t.Fatalf("replacement creator generation=%d, want 2", second.CreatorBundle.AccountGeneration)
	}
	if second.CreatorOneTimeKey.ID != 1 {
		t.Fatalf("replacement generation OTK id=%d, want 1", second.CreatorOneTimeKey.ID)
	}
}
