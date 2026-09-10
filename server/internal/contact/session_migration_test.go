package contact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestSQLiteStoreMigratesV1ToV2WithoutLosingM2Identity(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "kenato-v1.db")

	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqliteSchema); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA user_version = 1"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}

	bundle, _ := newSignedBundle(t, 0)
	encoded, err := EncodePublicIdentityBundle(bundle)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	payload, err := PublicationPayload(bundle)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if _, err := db.ExecContext(ctx, `
INSERT INTO identities(identity_id, publication_revision, payload_hash, bundle)
VALUES(?, ?, ?, ?)`, bundle.IdentityID, int64(bundle.PublicationRevision), digest[:], encoded); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenSQLiteStore(ctx, path)
	if err != nil {
		t.Fatalf("migrate v1 store: %v", err)
	}
	defer store.Close()

	var version int
	if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != sqliteSchemaVersion {
		t.Fatalf("schema version=%d, want %d", version, sqliteSchemaVersion)
	}

	stored, err := store.GetIdentity(ctx, bundle.IdentityID)
	if err != nil {
		t.Fatalf("read preserved M2 identity: %v", err)
	}
	if !bytes.Equal(stored.EncodedBundle, encoded) {
		t.Fatal("M2 identity changed during migration")
	}

	for _, table := range []string{"session_bootstraps", "session_one_time_prekeys", "session_reservations", "session_inits"} {
		var name string
		if err := store.db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name); err != nil {
			t.Fatalf("M3 table %s missing after migration: %v", table, err)
		}
		if name != table {
			t.Fatalf("M3 table=%q, want %q", name, table)
		}
	}
}
