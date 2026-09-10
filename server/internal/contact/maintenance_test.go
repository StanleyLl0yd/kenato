package contact

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneExpiredInvitesRemovesOnlyExpiredRows(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-test.db"))
	defer store.Close()

	now := time.Unix(2_000_000_000, 0).UTC()
	service := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, service, creator)

	first := signedInvite(t, creator, creatorKey, deterministicToken(71))
	if _, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: first}); err != nil {
		t.Fatal(err)
	}

	now = now.Add(time.Hour)
	second := signedInvite(t, creator, creatorKey, deterministicToken(72))
	if _, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: second}); err != nil {
		t.Fatal(err)
	}

	removed, err := store.PruneExpiredInvites(ctx, now.Add(InviteLifetime-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed=%d, want 1", removed)
	}

	var remaining int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM invites").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("remaining=%d, want 1", remaining)
	}
}

func TestPruneExpiredInvitesRejectsInvalidTime(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-test.db"))
	defer store.Close()

	if _, err := store.PruneExpiredInvites(ctx, time.Unix(-1, 0)); err == nil {
		t.Fatal("negative cleanup time accepted")
	}
}
