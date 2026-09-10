package contact

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteServiceInviteLifecycle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "kenato-test.db")
	store := openTestSQLiteStore(t, ctx, path)
	defer store.Close()

	now := time.Unix(2_000_000_000, 0).UTC()
	service := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 2)

	revision, err := service.PublishIdentity(ctx, PublishIdentityRequest{ProtocolVersion: ProtocolVersion, Bundle: creator})
	if err != nil || revision != 1 {
		t.Fatalf("publish creator: revision=%d err=%v", revision, err)
	}
	revision, err = service.PublishIdentity(ctx, PublishIdentityRequest{ProtocolVersion: ProtocolVersion, Bundle: creator})
	if err != nil || revision != 1 {
		t.Fatalf("idempotent publish: revision=%d err=%v", revision, err)
	}

	conflicting := cloneBundle(t, creator)
	conflicting.SignedPreKey.CreatedAtUnixSeconds++
	resignPublication(t, &conflicting, creatorKey)
	if _, err := service.PublishIdentity(ctx, PublishIdentityRequest{ProtocolVersion: ProtocolVersion, Bundle: conflicting}); !errors.Is(err, ErrPublicationConflict) {
		t.Fatalf("same-revision conflict error=%v", err)
	}

	creator = conflicting
	creator.PublicationRevision = 2
	resignPublication(t, &creator, creatorKey)
	if revision, err := service.PublishIdentity(ctx, PublishIdentityRequest{ProtocolVersion: ProtocolVersion, Bundle: creator}); err != nil || revision != 2 {
		t.Fatalf("publish revision 2: revision=%d err=%v", revision, err)
	}

	token := deterministicToken(1)
	invite := signedInvite(t, creator, creatorKey, token)
	expiresAt, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if expiresAt != now.Unix()+int64(InviteLifetime/time.Second) {
		t.Fatalf("expires_at=%d", expiresAt)
	}
	if retryExpiry, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite}); err != nil || retryExpiry != expiresAt {
		t.Fatalf("idempotent create: expires=%d err=%v", retryExpiry, err)
	}

	redeemer, redeemerKey := newSignedBundle(t, 1)
	redeemSignature := signedRedemption(t, creator.IdentityID, redeemer, redeemerKey, token)
	creatorResult, redeemedAt, err := service.RedeemInvite(ctx, RedeemInviteRequest{
		ProtocolVersion:     ProtocolVersion,
		Invite:              invite,
		RedeemerBundle:      redeemer,
		RedemptionSignature: redeemSignature,
	})
	if err != nil {
		t.Fatalf("redeem invite: %v", err)
	}
	if redeemedAt != now.Unix() || !bytes.Equal(creatorResult.IdentityID, creator.IdentityID) || creatorResult.PublicationRevision != 2 {
		t.Fatal("unexpected redemption result")
	}

	if _, retryAt, err := service.RedeemInvite(ctx, RedeemInviteRequest{
		ProtocolVersion:     ProtocolVersion,
		Invite:              invite,
		RedeemerBundle:      redeemer,
		RedemptionSignature: redeemSignature,
	}); err != nil || retryAt != redeemedAt {
		t.Fatalf("idempotent redemption: at=%d err=%v", retryAt, err)
	}

	claimPayload, err := ClaimPayload(creator.IdentityID, token)
	if err != nil {
		t.Fatal(err)
	}
	claimSignature := signPayload(t, creatorKey, claimPayload)
	redeemerResult, storedRedemptionProof, claimedRedeemedAt, err := service.ClaimInvite(ctx, ClaimInviteRequest{
		ProtocolVersion:   ProtocolVersion,
		CreatorIdentityID: creator.IdentityID,
		InviteToken:       token,
		ClaimSignature:    claimSignature,
	})
	if err != nil {
		t.Fatalf("claim invite: %v", err)
	}
	if !bytes.Equal(redeemerResult.IdentityID, redeemer.IdentityID) || !bytes.Equal(storedRedemptionProof, redeemSignature) || claimedRedeemedAt != redeemedAt {
		t.Fatal("unexpected claim result")
	}

	if _, _, _, err := service.ClaimInvite(ctx, ClaimInviteRequest{
		ProtocolVersion:   ProtocolVersion,
		CreatorIdentityID: creator.IdentityID,
		InviteToken:       token,
		ClaimSignature:    claimSignature,
	}); !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("claimed invite state was retained: %v", err)
	}
}

func TestSQLiteServiceRejectsSecondRedeemer(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-test.db"))
	defer store.Close()
	now := time.Unix(2_000_000_000, 0).UTC()
	service := newServiceWithClock(store, func() time.Time { return now })

	creator, creatorKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, service, creator)
	token := deterministicToken(3)
	invite := signedInvite(t, creator, creatorKey, token)
	if _, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite}); err != nil {
		t.Fatal(err)
	}

	first, firstKey := newSignedBundle(t, 0)
	firstProof := signedRedemption(t, creator.IdentityID, first, firstKey, token)
	if _, _, err := service.RedeemInvite(ctx, RedeemInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite, RedeemerBundle: first, RedemptionSignature: firstProof}); err != nil {
		t.Fatal(err)
	}

	second, secondKey := newSignedBundle(t, 0)
	secondProof := signedRedemption(t, creator.IdentityID, second, secondKey, token)
	if _, _, err := service.RedeemInvite(ctx, RedeemInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite, RedeemerBundle: second, RedemptionSignature: secondProof}); !errors.Is(err, ErrInviteAlreadyUsed) {
		t.Fatalf("second redeemer error=%v", err)
	}
}

func TestSQLiteServiceInviteExpiry(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-test.db"))
	defer store.Close()
	now := time.Unix(2_000_000_000, 0).UTC()
	service := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, service, creator)
	token := deterministicToken(4)
	invite := signedInvite(t, creator, creatorKey, token)
	if _, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite}); err != nil {
		t.Fatal(err)
	}

	redeemer, redeemerKey := newSignedBundle(t, 0)
	proof := signedRedemption(t, creator.IdentityID, redeemer, redeemerKey, token)
	now = now.Add(InviteLifetime)
	if _, _, err := service.RedeemInvite(ctx, RedeemInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite, RedeemerBundle: redeemer, RedemptionSignature: proof}); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("expired redemption error=%v", err)
	}
}

func TestSQLiteStorePersistsIdentityAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "kenato-test.db")
	now := time.Unix(2_000_000_000, 0).UTC()
	bundle, _ := newSignedBundle(t, 0)

	store := openTestSQLiteStore(t, ctx, path)
	service := newServiceWithClock(store, func() time.Time { return now })
	mustPublish(t, ctx, service, bundle)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openTestSQLiteStore(t, ctx, path)
	defer store.Close()
	service = newServiceWithClock(store, func() time.Time { return now })
	loaded, err := service.loadIdentity(ctx, bundle.IdentityID)
	if err != nil {
		t.Fatalf("load persisted identity: %v", err)
	}
	if !bytes.Equal(loaded.IdentityPublicKey, bundle.IdentityPublicKey) {
		t.Fatal("persisted identity public key mismatch")
	}

	var journalMode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil || journalMode != "wal" {
		t.Fatalf("journal_mode=%q err=%v", journalMode, err)
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("database file missing or non-regular: %v", err)
	}
}

func TestSQLiteServiceInviteQuota(t *testing.T) {
	ctx := context.Background()
	store := openTestSQLiteStore(t, ctx, filepath.Join(t.TempDir(), "kenato-test.db"))
	defer store.Close()
	now := time.Unix(2_000_000_000, 0).UTC()
	service := newServiceWithClock(store, func() time.Time { return now })
	creator, creatorKey := newSignedBundle(t, 0)
	mustPublish(t, ctx, service, creator)

	for i := 0; i < MaxActiveInvitesPerIdentity; i++ {
		invite := signedInvite(t, creator, creatorKey, deterministicToken(byte(i+10)))
		if _, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: invite}); err != nil {
			t.Fatalf("create invite %d: %v", i, err)
		}
	}
	extra := signedInvite(t, creator, creatorKey, deterministicToken(99))
	if _, err := service.CreateInvite(ctx, CreateInviteRequest{ProtocolVersion: ProtocolVersion, Invite: extra}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("quota error=%v", err)
	}
}

func openTestSQLiteStore(t *testing.T, ctx context.Context, path string) *SQLiteStore {
	t.Helper()
	store, err := OpenSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore: %v", err)
	}
	return store
}

func mustPublish(t *testing.T, ctx context.Context, service *Service, bundle PublicIdentityBundle) {
	t.Helper()
	if _, err := service.PublishIdentity(ctx, PublishIdentityRequest{ProtocolVersion: ProtocolVersion, Bundle: bundle}); err != nil {
		t.Fatalf("publish identity: %v", err)
	}
}

func deterministicToken(seed byte) []byte {
	token := make([]byte, InviteTokenBytes)
	for i := range token {
		token[i] = seed + byte(i)
	}
	return token
}

func signedInvite(t *testing.T, creator PublicIdentityBundle, creatorKey *ecdsa.PrivateKey, token []byte) InviteDescriptor {
	t.Helper()
	payload, err := InvitePayload(creator.IdentityID, token)
	if err != nil {
		t.Fatal(err)
	}
	return InviteDescriptor{
		CreatorIdentityID: bytes.Clone(creator.IdentityID),
		InviteToken:       bytes.Clone(token),
		InviteSignature:   signPayload(t, creatorKey, payload),
	}
}

func signedRedemption(t *testing.T, creatorID []byte, redeemer PublicIdentityBundle, redeemerKey *ecdsa.PrivateKey, token []byte) []byte {
	payload, err := RedemptionPayload(creatorID, redeemer.IdentityID, token)
	if err != nil {
		t.Fatal(err)
	}
	return signPayload(t, redeemerKey, payload)
}

func resignPublication(t *testing.T, bundle *PublicIdentityBundle, identityKey *ecdsa.PrivateKey) {
	t.Helper()
	payload, err := PublicationPayload(*bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.PublicationSignature = signPayload(t, identityKey, payload)
}

func cloneBundle(t *testing.T, bundle PublicIdentityBundle) PublicIdentityBundle {
	t.Helper()
	encoded, err := EncodePublicIdentityBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := DecodePublicIdentityBundle(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}
