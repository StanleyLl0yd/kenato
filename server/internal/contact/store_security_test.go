package contact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStoreSecurityConfigurationAndPermissions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "kenato-test.db")
	store := openTestSQLiteStore(t, ctx, path)
	defer store.Close()

	bundle, _ := newSignedBundle(t, 0)
	service := newServiceWithClock(store, func() time.Time { return time.Unix(2_000_000_000, 0).UTC() })
	mustPublish(t, ctx, service, bundle)

	var foreignKeys int
	if err := store.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("foreign_keys=%d err=%v", foreignKeys, err)
	}
	var synchronous int
	if err := store.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		t.Fatalf("synchronous=%d err=%v", synchronous, err)
	}

	matches, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("SQLite database files not found")
	}
	for _, name := range matches {
		info, err := os.Lstat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", filepath.Base(name), err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("SQLite artifact %s is not a regular file", filepath.Base(name))
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("SQLite artifact %s has overly broad permissions %04o", filepath.Base(name), info.Mode().Perm())
		}
	}
}

func TestSQLiteStoreRejectsSymlinkDatabasePath(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "kenato.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenSQLiteStore(ctx, link); err == nil {
		_ = store.Close()
		t.Fatal("symlink database path accepted")
	}
}

func TestSQLiteServiceClaimExpiresAtBoundary(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-test.db"))
	defer store.Close()

	now := time.Unix(2_000_000_000, 0).UTC()
	service := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, service, creator)

	token := deterministicToken(61)
	invite := signedInvite(t, creator, creatorKey, token)
	if _, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite}); err != nil {
		t.Fatal(err)
	}
	redeemer, redeemerKey := newSignedBundle(t, 0)
	proof := signedRedemption(t, creator.IdentityID, redeemer, redeemerKey, token)
	if _, _, err := service.RedeemInvite(ctx, RedeemInviteRequest{
		ProtocolVersion:     ProtocolVersion,
		Invite:              invite,
		RedeemerBundle:      redeemer,
		RedemptionSignature: proof,
	}); err != nil {
		t.Fatal(err)
	}

	claimPayload, err := ClaimPayload(creator.IdentityID, token)
	if err != nil {
		t.Fatal(err)
	}
	claimSignature := signPayload(t, creatorKey, claimPayload)
	now = now.Add(InviteLifetime)
	_, _, _, err = service.ClaimInvite(ctx, ClaimInviteRequest{
		ProtocolVersion:   ProtocolVersion,
		CreatorIdentityID: creator.IdentityID,
		InviteToken:       token,
		ClaimSignature:    claimSignature,
	})
	if !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("claim at expiry boundary error=%v", err)
	}
}
