package contact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	sqliteSchemaVersion    = 1
	setSQLiteSchemaVersion = "PRAGMA user_version = 1"
)

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS identities (
    identity_id BLOB PRIMARY KEY NOT NULL CHECK(length(identity_id) = 32),
    publication_revision INTEGER NOT NULL CHECK(publication_revision > 0),
    payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32),
    bundle BLOB NOT NULL CHECK(length(bundle) BETWEEN 1 AND 65536)
) STRICT;

CREATE TABLE IF NOT EXISTS invites (
    token_hash BLOB PRIMARY KEY NOT NULL CHECK(length(token_hash) = 32),
    creator_identity_id BLOB NOT NULL CHECK(length(creator_identity_id) = 32),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
    redeemed_at INTEGER CHECK(redeemed_at IS NULL OR redeemed_at >= created_at),
    redeemer_identity_id BLOB CHECK(redeemer_identity_id IS NULL OR length(redeemer_identity_id) = 32),
    redemption_signature BLOB CHECK(redemption_signature IS NULL OR length(redemption_signature) BETWEEN 1 AND 2048),
    FOREIGN KEY (creator_identity_id) REFERENCES identities(identity_id) ON DELETE CASCADE,
    FOREIGN KEY (redeemer_identity_id) REFERENCES identities(identity_id) ON DELETE RESTRICT,
    CHECK (
        (redeemed_at IS NULL AND redeemer_identity_id IS NULL AND redemption_signature IS NULL)
        OR
        (redeemed_at IS NOT NULL AND redeemer_identity_id IS NOT NULL AND redemption_signature IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS invites_creator_expiry_idx
    ON invites(creator_identity_id, expires_at);
CREATE INDEX IF NOT EXISTS invites_expiry_idx
    ON invites(expires_at);
`

type SQLiteStore struct {
	db      *sql.DB
	writeMu sync.Mutex
}

func OpenSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("sqlite path must not be empty")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve sqlite path: %w", err)
	}
	parent := filepath.Dir(absolutePath)
	info, err := os.Stat(parent)
	if err != nil {
		return nil, fmt.Errorf("stat sqlite directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("sqlite parent path is not a directory")
	}
	if err := prepareDatabaseFile(absolutePath); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", sqliteDSN(absolutePath))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(0)

	store := &SQLiteStore{db: db}
	if err := store.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func prepareDatabaseFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		return file.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create sqlite file: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect sqlite file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("sqlite path must reference a regular file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict sqlite file permissions: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func sqliteDSN(path string) string {
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := u.Query()
	query.Set("_busy_timeout", "5000")
	query.Set("_foreign_keys", "on")
	query.Set("_journal_mode", "WAL")
	query.Set("_synchronous", "FULL")
	query.Set("_defensive", "1")
	query.Set("_dqs", "0")
	u.RawQuery = query.Encode()
	return u.String()
}

func (s *SQLiteStore) initialize(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping sqlite: %w", err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read sqlite schema version: %w", err)
	}
	if version != 0 && version != sqliteSchemaVersion {
		return fmt.Errorf("unsupported sqlite schema version %d", version)
	}
	if _, err := s.db.ExecContext(ctx, sqliteSchema); err != nil {
		return fmt.Errorf("initialize sqlite schema: %w", err)
	}
	if version == 0 {
		if _, err := s.db.ExecContext(ctx, setSQLiteSchemaVersion); err != nil {
			return fmt.Errorf("set sqlite schema version: %w", err)
		}
	}

	var journalMode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("read sqlite journal mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("sqlite WAL mode is required, got %q", journalMode)
	}
	return nil
}

func (s *SQLiteStore) PublishIdentity(ctx context.Context, record PublicationRecord) (uint64, error) {
	if err := validatePublicationRecord(record); err != nil {
		return 0, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin identity publication: %w", err)
	}
	defer tx.Rollback()

	revision, err := publishIdentityTx(ctx, tx, record)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit identity publication: %w", err)
	}
	return revision, nil
}

func (s *SQLiteStore) GetIdentity(ctx context.Context, identityID []byte) (StoredIdentity, error) {
	if len(identityID) != IdentityIDBytes {
		return StoredIdentity{}, ErrIdentityNotFound
	}
	var encoded []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT bundle FROM identities WHERE identity_id = ?",
		identityID,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredIdentity{}, ErrIdentityNotFound
	}
	if err != nil {
		return StoredIdentity{}, fmt.Errorf("read identity: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > MaxWireMessageBytes {
		return StoredIdentity{}, errors.New("stored identity bundle violates size bound")
	}
	return StoredIdentity{EncodedBundle: bytes.Clone(encoded)}, nil
}

func (s *SQLiteStore) CreateInvite(
	ctx context.Context,
	tokenHash [sha256.Size]byte,
	creatorIdentityID []byte,
	createdAt int64,
	expiresAt int64,
) (int64, error) {
	if len(creatorIdentityID) != IdentityIDBytes || createdAt < 0 || expiresAt-createdAt != int64(InviteLifetime/time.Second) {
		return 0, ErrInvalidInvite
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin invite creation: %w", err)
	}
	defer tx.Rollback()

	if err := requireIdentityTx(ctx, tx, creatorIdentityID); err != nil {
		return 0, err
	}

	var existingCreator []byte
	var existingExpiry int64
	var existingRedeemed sql.NullInt64
	err = tx.QueryRowContext(ctx,
		"SELECT creator_identity_id, expires_at, redeemed_at FROM invites WHERE token_hash = ?",
		tokenHash[:],
	).Scan(&existingCreator, &existingExpiry, &existingRedeemed)
	switch {
	case err == nil:
		if !bytes.Equal(existingCreator, creatorIdentityID) {
			return 0, ErrInvalidInvite
		}
		if existingRedeemed.Valid {
			return 0, ErrInviteAlreadyUsed
		}
		if existingExpiry <= createdAt {
			return 0, ErrInviteExpired
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("commit idempotent invite creation: %w", err)
		}
		return existingExpiry, nil
	case !errors.Is(err, sql.ErrNoRows):
		return 0, fmt.Errorf("read existing invite: %w", err)
	}

	if _, err := tx.ExecContext(ctx, "DELETE FROM invites WHERE expires_at <= ?", createdAt); err != nil {
		return 0, fmt.Errorf("prune expired invites: %w", err)
	}

	var active int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM invites WHERE creator_identity_id = ? AND expires_at > ?",
		creatorIdentityID,
		createdAt,
	).Scan(&active); err != nil {
		return 0, fmt.Errorf("count active invites: %w", err)
	}
	if active >= MaxActiveInvitesPerIdentity {
		return 0, ErrCapacity
	}
	var total int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM invites").Scan(&total); err != nil {
		return 0, fmt.Errorf("count invites: %w", err)
	}
	if total >= MaxStoredInvites {
		return 0, ErrCapacity
	}

	if _, err := tx.ExecContext(ctx,
		"INSERT INTO invites(token_hash, creator_identity_id, created_at, expires_at) VALUES(?, ?, ?, ?)",
		tokenHash[:], creatorIdentityID, createdAt, expiresAt,
	); err != nil {
		return 0, fmt.Errorf("insert invite: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit invite creation: %w", err)
	}
	return expiresAt, nil
}

func (s *SQLiteStore) RedeemInvite(ctx context.Context, record RedeemRecord) (RedeemResult, error) {
	if len(record.CreatorIdentityID) != IdentityIDBytes || record.RedeemedAt < 0 || !validSignature(record.RedemptionSignature) {
		return RedeemResult{}, ErrInvalidInvite
	}
	if err := validatePublicationRecord(record.RedeemerPublication); err != nil {
		return RedeemResult{}, err
	}
	if bytes.Equal(record.CreatorIdentityID, record.RedeemerPublication.Bundle.IdentityID) {
		return RedeemResult{}, ErrSelfInvite
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RedeemResult{}, fmt.Errorf("begin invite redemption: %w", err)
	}
	defer tx.Rollback()

	var creatorID []byte
	var expiresAt int64
	var redeemedAt sql.NullInt64
	var redeemerID []byte
	err = tx.QueryRowContext(ctx,
		"SELECT creator_identity_id, expires_at, redeemed_at, redeemer_identity_id FROM invites WHERE token_hash = ?",
		record.TokenHash[:],
	).Scan(&creatorID, &expiresAt, &redeemedAt, &redeemerID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !bytes.Equal(creatorID, record.CreatorIdentityID)) {
		return RedeemResult{}, ErrInviteNotFound
	}
	if err != nil {
		return RedeemResult{}, fmt.Errorf("read invite for redemption: %w", err)
	}
	if expiresAt <= record.RedeemedAt {
		if _, deleteErr := tx.ExecContext(ctx, "DELETE FROM invites WHERE token_hash = ?", record.TokenHash[:]); deleteErr != nil {
			return RedeemResult{}, fmt.Errorf("delete expired invite: %w", deleteErr)
		}
		if err := tx.Commit(); err != nil {
			return RedeemResult{}, fmt.Errorf("commit expired invite deletion: %w", err)
		}
		return RedeemResult{}, ErrInviteExpired
	}
	if redeemedAt.Valid {
		if bytes.Equal(redeemerID, record.RedeemerPublication.Bundle.IdentityID) {
			if err := tx.Commit(); err != nil {
				return RedeemResult{}, fmt.Errorf("commit idempotent redemption: %w", err)
			}
			return RedeemResult{RedeemedAt: redeemedAt.Int64}, nil
		}
		return RedeemResult{}, ErrInviteAlreadyUsed
	}

	if _, err := publishIdentityTx(ctx, tx, record.RedeemerPublication); err != nil {
		return RedeemResult{}, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE invites
SET redeemed_at = ?, redeemer_identity_id = ?, redemption_signature = ?
WHERE token_hash = ? AND redeemed_at IS NULL`,
		record.RedeemedAt,
		record.RedeemerPublication.Bundle.IdentityID,
		record.RedemptionSignature,
		record.TokenHash[:],
	)
	if err != nil {
		return RedeemResult{}, fmt.Errorf("redeem invite: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return RedeemResult{}, ErrInviteAlreadyUsed
	}
	if err := tx.Commit(); err != nil {
		return RedeemResult{}, fmt.Errorf("commit invite redemption: %w", err)
	}
	return RedeemResult{RedeemedAt: record.RedeemedAt}, nil
}

func (s *SQLiteStore) ClaimInvite(ctx context.Context, record ClaimRecord) (ClaimResult, error) {
	if len(record.CreatorIdentityID) != IdentityIDBytes || record.ClaimedAt < 0 {
		return ClaimResult{}, ErrInvalidInvite
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("begin invite claim: %w", err)
	}
	defer tx.Rollback()

	var creatorID []byte
	var expiresAt int64
	var redeemedAt sql.NullInt64
	var redeemerID []byte
	var redemptionSignature []byte
	err = tx.QueryRowContext(ctx, `
SELECT creator_identity_id, expires_at, redeemed_at, redeemer_identity_id, redemption_signature
FROM invites WHERE token_hash = ?`, record.TokenHash[:]).Scan(
		&creatorID, &expiresAt, &redeemedAt, &redeemerID, &redemptionSignature,
	)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !bytes.Equal(creatorID, record.CreatorIdentityID)) {
		return ClaimResult{}, ErrInviteNotFound
	}
	if err != nil {
		return ClaimResult{}, fmt.Errorf("read invite for claim: %w", err)
	}
	if expiresAt <= record.ClaimedAt {
		if _, deleteErr := tx.ExecContext(ctx, "DELETE FROM invites WHERE token_hash = ?", record.TokenHash[:]); deleteErr != nil {
			return ClaimResult{}, fmt.Errorf("delete expired invite: %w", deleteErr)
		}
		if err := tx.Commit(); err != nil {
			return ClaimResult{}, fmt.Errorf("commit expired invite deletion: %w", err)
		}
		return ClaimResult{}, ErrInviteExpired
	}
	if !redeemedAt.Valid || len(redeemerID) != IdentityIDBytes || !validSignature(redemptionSignature) {
		return ClaimResult{}, ErrInviteNotRedeemed
	}

	var redeemerBundle []byte
	if err := tx.QueryRowContext(ctx,
		"SELECT bundle FROM identities WHERE identity_id = ?",
		redeemerID,
	).Scan(&redeemerBundle); err != nil {
		return ClaimResult{}, fmt.Errorf("read redeemer identity: %w", err)
	}
	if len(redeemerBundle) == 0 || len(redeemerBundle) > MaxWireMessageBytes {
		return ClaimResult{}, errors.New("stored redeemer bundle violates size bound")
	}
	result, err := tx.ExecContext(ctx,
		"DELETE FROM invites WHERE token_hash = ? AND creator_identity_id = ?",
		record.TokenHash[:], record.CreatorIdentityID,
	)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("delete claimed invite: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ClaimResult{}, ErrInviteNotFound
	}
	if err := tx.Commit(); err != nil {
		return ClaimResult{}, fmt.Errorf("commit invite claim: %w", err)
	}
	return ClaimResult{
		RedeemerBundle:      bytes.Clone(redeemerBundle),
		RedemptionSignature: bytes.Clone(redemptionSignature),
		RedeemedAt:          redeemedAt.Int64,
	}, nil
}

func publishIdentityTx(ctx context.Context, tx *sql.Tx, record PublicationRecord) (uint64, error) {
	var existingRevision int64
	var existingHash []byte
	err := tx.QueryRowContext(ctx,
		"SELECT publication_revision, payload_hash FROM identities WHERE identity_id = ?",
		record.Bundle.IdentityID,
	).Scan(&existingRevision, &existingHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		var total int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM identities").Scan(&total); err != nil {
			return 0, fmt.Errorf("count identities: %w", err)
		}
		if total >= MaxStoredIdentities {
			return 0, ErrCapacity
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO identities(identity_id, publication_revision, payload_hash, bundle)
VALUES(?, ?, ?, ?)`,
			record.Bundle.IdentityID,
			int64(record.Bundle.PublicationRevision),
			record.PayloadHash[:],
			record.EncodedBundle,
		)
		if err != nil {
			return 0, fmt.Errorf("insert identity: %w", err)
		}
		return record.Bundle.PublicationRevision, nil
	case err != nil:
		return 0, fmt.Errorf("read identity publication: %w", err)
	}

	newRevision := record.Bundle.PublicationRevision
	if newRevision < uint64(existingRevision) {
		return 0, ErrPublicationConflict
	}
	if newRevision == uint64(existingRevision) {
		if len(existingHash) == sha256.Size && bytes.Equal(existingHash, record.PayloadHash[:]) {
			return newRevision, nil
		}
		return 0, ErrPublicationConflict
	}
	result, err := tx.ExecContext(ctx, `
UPDATE identities
SET publication_revision = ?, payload_hash = ?, bundle = ?
WHERE identity_id = ? AND publication_revision = ?`,
		int64(newRevision),
		record.PayloadHash[:],
		record.EncodedBundle,
		record.Bundle.IdentityID,
		existingRevision,
	)
	if err != nil {
		return 0, fmt.Errorf("update identity: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return 0, ErrPublicationConflict
	}
	return newRevision, nil
}

func requireIdentityTx(ctx context.Context, tx *sql.Tx, identityID []byte) error {
	var one int
	err := tx.QueryRowContext(ctx, "SELECT 1 FROM identities WHERE identity_id = ?", identityID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIdentityNotFound
	}
	if err != nil {
		return fmt.Errorf("check identity: %w", err)
	}
	return nil
}

func validatePublicationRecord(record PublicationRecord) error {
	if err := validateSignedBundleShape(record.Bundle); err != nil {
		return err
	}
	if record.Bundle.PublicationRevision > math.MaxInt64 {
		return ErrInvalidBundle
	}
	if len(record.EncodedBundle) == 0 || len(record.EncodedBundle) > MaxWireMessageBytes {
		return ErrInvalidBundle
	}
	return nil
}
