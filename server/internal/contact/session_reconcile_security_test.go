package contact

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteExpiredReservationDoesNotBlockFreshPreKeyPublication(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-session.db"))
	defer store.Close()

	now := time.Unix(2_100_000_000, 0).UTC()
	contacts := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	firstRedeemer, firstRedeemerKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, creator)
	mustPublish(t, ctx, contacts, firstRedeemer)

	sessions := newSessionServiceWithClock(store, store, func() int64 { return now.Unix() })
	creatorSession := newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 1)
	mustPublishSession(t, ctx, sessions, creatorSession)

	firstToken := establishRedeemedInvite(
		t,
		ctx,
		contacts,
		creator,
		creatorKey,
		firstRedeemer,
		firstRedeemerKey,
		deterministicToken(0x71),
	)
	firstReservation := reserveSessionForInvite(
		t,
		ctx,
		sessions,
		creator,
		firstRedeemer,
		firstRedeemerKey,
		firstToken,
	)
	if firstReservation.CreatorOneTimeKey.ID != 1 {
		t.Fatalf("first reserved prekey id = %d, want 1", firstReservation.CreatorOneTimeKey.ID)
	}

	now = now.Add(InviteLifetime)
	removed, err := store.PruneExpiredInvites(ctx, now)
	if err != nil {
		t.Fatalf("prune expired invite: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expired invite rows removed = %d, want 1", removed)
	}
	assertSessionTemporaryRows(t, store, 0, 0)

	freshKey := bytes.Repeat([]byte{0x7a}, OlmPublicKeyBytes)
	replenished := cloneSessionBundle(creatorSession)
	replenished.PublicationRevision = 2
	replenished.OneTimePreKeys = append(replenished.OneTimePreKeys, SessionOneTimePreKey{
		ID:        2,
		PublicKey: freshKey,
	})
	resignSessionBundle(t, &replenished, creatorKey)
	mustPublishSession(t, ctx, sessions, replenished)

	var staleRows int
	if err := store.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM session_one_time_prekeys
WHERE identity_id = ? AND account_generation = ? AND key_id = ?`,
		creator.IdentityID,
		1,
		firstReservation.CreatorOneTimeKey.ID,
	).Scan(&staleRows); err != nil {
		t.Fatal(err)
	}
	if staleRows != 0 {
		t.Fatalf("expired reserved prekey became available again: rows=%d", staleRows)
	}

	secondRedeemer, secondRedeemerKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, contacts, secondRedeemer)
	secondToken := establishRedeemedInvite(
		t,
		ctx,
		contacts,
		creator,
		creatorKey,
		secondRedeemer,
		secondRedeemerKey,
		deterministicToken(0x72),
	)
	secondReservation := reserveSessionForInvite(
		t,
		ctx,
		sessions,
		creator,
		secondRedeemer,
		secondRedeemerKey,
		secondToken,
	)
	if secondReservation.CreatorOneTimeKey.ID != 2 || !bytes.Equal(secondReservation.CreatorOneTimeKey.PublicKey, freshKey) {
		t.Fatalf("fresh reservation = id %d, want newly published id 2", secondReservation.CreatorOneTimeKey.ID)
	}
}

func TestSQLiteSessionPublicationRejectsReservedPublicKeyUnderNewID(t *testing.T) {
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
	initial := newSignedSessionBundle(t, creator.IdentityID, creatorKey, 1, 1, 2)
	mustPublishSession(t, ctx, sessions, initial)

	token := establishRedeemedInvite(
		t,
		ctx,
		contacts,
		creator,
		creatorKey,
		redeemer,
		redeemerKey,
		deterministicToken(0x73),
	)
	reserved := reserveSessionForInvite(t, ctx, sessions, creator, redeemer, redeemerKey, token)
	if reserved.CreatorOneTimeKey.ID != initial.OneTimePreKeys[0].ID {
		t.Fatal("unexpected reserved prekey")
	}

	aliased := cloneSessionBundle(initial)
	aliased.PublicationRevision = 2
	aliased.OneTimePreKeys = []SessionOneTimePreKey{
		cloneSessionOneTimePreKey(initial.OneTimePreKeys[1]),
		{
			ID:        initial.OneTimePreKeys[1].ID + 1,
			PublicKey: bytes.Clone(reserved.CreatorOneTimeKey.PublicKey),
		},
	}
	resignSessionBundle(t, &aliased, creatorKey)
	if _, _, err := sessions.PublishSessionBootstrap(ctx, PublishSessionBootstrapRequest{
		ProtocolVersion: SessionProtocolVersion,
		Bundle:          aliased,
	}); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("reserved prekey alias error = %v, want %v", err, ErrSessionConflict)
	}
}
