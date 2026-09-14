package messaging

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	mailboxSQLiteSchemaVersion = 1
	setMailboxSchemaVersion    = "PRAGMA user_version = 1"
)

const mailboxSQLiteSchema = `
CREATE TABLE IF NOT EXISTS mailbox_messages (
    mailbox_id INTEGER PRIMARY KEY,
    sender_identity_id BLOB NOT NULL CHECK(length(sender_identity_id) = 32),
    recipient_identity_id BLOB NOT NULL CHECK(length(recipient_identity_id) = 32),
    message_id BLOB NOT NULL CHECK(length(message_id) = 16),
    accepted_at INTEGER NOT NULL CHECK(accepted_at >= 0),
    expires_at INTEGER NOT NULL CHECK(expires_at > accepted_at AND expires_at - accepted_at <= 259200),
    ciphertext_size INTEGER NOT NULL CHECK(ciphertext_size BETWEEN 1 AND 65536),
    encoded_envelope BLOB NOT NULL CHECK(length(encoded_envelope) BETWEEN 1 AND 98304),
    UNIQUE(sender_identity_id, message_id),
    CHECK(sender_identity_id <> recipient_identity_id)
) STRICT;

CREATE INDEX IF NOT EXISTS mailbox_recipient_delivery_idx
    ON mailbox_messages(recipient_identity_id, expires_at, mailbox_id);
CREATE INDEX IF NOT EXISTS mailbox_sender_idx
    ON mailbox_messages(sender_identity_id, mailbox_id);
CREATE INDEX IF NOT EXISTS mailbox_expiry_idx
    ON mailbox_messages(expires_at, mailbox_id);

CREATE TRIGGER IF NOT EXISTS mailbox_capacity_guard
BEFORE INSERT ON mailbox_messages
FOR EACH ROW
BEGIN
    SELECT CASE WHEN (
        SELECT COUNT(*) FROM mailbox_messages
        WHERE recipient_identity_id = NEW.recipient_identity_id
    ) >= 500 THEN RAISE(ABORT, 'mailbox capacity') END;
    SELECT CASE WHEN COALESCE((
        SELECT SUM(length(encoded_envelope)) FROM mailbox_messages
        WHERE recipient_identity_id = NEW.recipient_identity_id
    ), 0) + length(NEW.encoded_envelope) > 16777216
        THEN RAISE(ABORT, 'mailbox capacity') END;
    SELECT CASE WHEN (
        SELECT COUNT(*) FROM mailbox_messages
        WHERE sender_identity_id = NEW.sender_identity_id
    ) >= 1000 THEN RAISE(ABORT, 'mailbox capacity') END;
    SELECT CASE WHEN COALESCE((
        SELECT SUM(length(encoded_envelope)) FROM mailbox_messages
        WHERE sender_identity_id = NEW.sender_identity_id
    ), 0) + length(NEW.encoded_envelope) > 33554432
        THEN RAISE(ABORT, 'mailbox capacity') END;
    SELECT CASE WHEN (SELECT COUNT(*) FROM mailbox_messages) >= 100000
        THEN RAISE(ABORT, 'mailbox capacity') END;
    SELECT CASE WHEN COALESCE((
        SELECT SUM(length(encoded_envelope)) FROM mailbox_messages
    ), 0) + length(NEW.encoded_envelope) > 268435456
        THEN RAISE(ABORT, 'mailbox capacity') END;
END;
`

type SQLiteMailboxStore struct {
	db      *sql.DB
	writeMu sync.Mutex
}

func OpenSQLiteMailboxStore(ctx context.Context, path string) (*SQLiteMailboxStore, error) {
	return openSQLiteMailboxStoreWithClock(ctx, path, time.Now)
}

func openSQLiteMailboxStoreWithClock(ctx context.Context, path string, clock func() time.Time) (*SQLiteMailboxStore, error) {
	path = strings.TrimSpace(path)
	if path == "" || clock == nil {
		return nil, errors.New("mailbox sqlite configuration is invalid")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve mailbox sqlite path: %w", err)
	}
	parent := filepath.Dir(absolutePath)
	info, err := os.Stat(parent)
	if err != nil {
		return nil, fmt.Errorf("stat mailbox sqlite directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("mailbox sqlite parent path is not a directory")
	}
	if err := prepareMailboxDatabaseFile(absolutePath); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", mailboxSQLiteDSN(absolutePath))
	if err != nil {
		return nil, fmt.Errorf("open mailbox sqlite: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(0)

	store := &SQLiteMailboxStore{db: db}
	if err := store.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := store.PruneExpired(ctx, clock().UTC()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("startup mailbox cleanup: %w", err)
	}
	return store, nil
}

func (s *SQLiteMailboxStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func prepareMailboxDatabaseFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		return file.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create mailbox file: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect mailbox file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("mailbox path must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("set mailbox file mode: %w", err)
		}
	}
	return nil
}

func mailboxSQLiteDSN(path string) string {
	query := url.Values{}
	query.Set("_busy_timeout", "5000")
	query.Set("_journal_mode", "WAL")
	query.Set("_synchronous", "FULL")
	query.Set("_defensive", "1")
	query.Set("_dqs", "0")
	return "file:" + filepath.ToSlash(path) + "?" + query.Encode()
}

func (s *SQLiteMailboxStore) initialize(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read mailbox schema version: %w", err)
	}
	if version > mailboxSQLiteSchemaVersion {
		return fmt.Errorf("mailbox schema version %d is newer than supported %d", version, mailboxSQLiteSchemaVersion)
	}
	if _, err := s.db.ExecContext(ctx, mailboxSQLiteSchema); err != nil {
		return fmt.Errorf("initialize mailbox schema: %w", err)
	}
	if version < mailboxSQLiteSchemaVersion {
		if _, err := s.db.ExecContext(ctx, setMailboxSchemaVersion); err != nil {
			return fmt.Errorf("set mailbox schema version: %w", err)
		}
	}
	var journalMode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("read mailbox journal mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("mailbox sqlite WAL mode is required, got %q", journalMode)
	}
	return nil
}

func (s *SQLiteMailboxStore) PutMailbox(ctx context.Context, record MailboxRecord) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("mailbox store is unavailable")
	}
	if err := validateMailboxRecord(record); err != nil {
		return false, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin mailbox insert: %w", err)
	}
	defer tx.Rollback()
	if _, err := pruneExpiredMailboxTx(ctx, tx, record.AcceptedAtUnixSeconds, MaxMailboxCleanupBatch); err != nil {
		return false, err
	}

	var recipient []byte
	var expiresAt int64
	var ciphertextSize int
	var encoded []byte
	err = tx.QueryRowContext(ctx, `
SELECT recipient_identity_id, expires_at, ciphertext_size, encoded_envelope
FROM mailbox_messages
WHERE sender_identity_id = ? AND message_id = ?`, record.Envelope.SenderIdentityID, record.Envelope.MessageID).Scan(
		&recipient, &expiresAt, &ciphertextSize, &encoded,
	)
	switch {
	case err == nil:
		if bytes.Equal(recipient, record.Envelope.RecipientIdentityID) &&
			expiresAt == record.Envelope.ExpiresAtUnixSeconds &&
			ciphertextSize == len(record.Envelope.Ciphertext) &&
			bytes.Equal(encoded, record.EncodedEnvelope) {
			if err := tx.Commit(); err != nil {
				return false, fmt.Errorf("commit idempotent mailbox insert: %w", err)
			}
			return false, nil
		}
		return false, ErrMailboxRejected
	case !errors.Is(err, sql.ErrNoRows):
		return false, fmt.Errorf("read mailbox duplicate: %w", err)
	}

	if err := checkMailboxCapacityTx(ctx, tx, record.Envelope.SenderIdentityID, record.Envelope.RecipientIdentityID, int64(len(record.EncodedEnvelope))); err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO mailbox_messages(
    sender_identity_id, recipient_identity_id, message_id,
    accepted_at, expires_at, ciphertext_size, encoded_envelope
) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		record.Envelope.SenderIdentityID,
		record.Envelope.RecipientIdentityID,
		record.Envelope.MessageID,
		record.AcceptedAtUnixSeconds,
		record.Envelope.ExpiresAtUnixSeconds,
		len(record.Envelope.Ciphertext),
		record.EncodedEnvelope,
	)
	if err != nil {
		if strings.Contains(err.Error(), "mailbox capacity") {
			return false, ErrMailboxCapacity
		}
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return false, ErrMailboxRejected
		}
		return false, fmt.Errorf("insert mailbox message: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit mailbox insert: %w", err)
	}
	return true, nil
}

func (s *SQLiteMailboxStore) ListMailbox(ctx context.Context, recipientIdentityID []byte, nowUnixSeconds int64, limit int) ([]MailboxDelivery, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("mailbox store is unavailable")
	}
	if len(recipientIdentityID) != IdentityIDBytes || nowUnixSeconds < 0 || limit <= 0 || limit > MaxMailboxDeliveryPage {
		return nil, ErrMailboxRejected
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT sender_identity_id, message_id, accepted_at, expires_at, ciphertext_size, encoded_envelope
FROM mailbox_messages
WHERE recipient_identity_id = ? AND expires_at > ?
ORDER BY mailbox_id
LIMIT ?`, recipientIdentityID, nowUnixSeconds, limit)
	if err != nil {
		return nil, fmt.Errorf("list mailbox messages: %w", err)
	}
	defer rows.Close()

	out := make([]MailboxDelivery, 0, limit)
	for rows.Next() {
		var sender, messageID, encoded []byte
		var acceptedAt, expiresAt int64
		var ciphertextSize int
		if err := rows.Scan(&sender, &messageID, &acceptedAt, &expiresAt, &ciphertextSize, &encoded); err != nil {
			return nil, fmt.Errorf("scan mailbox message: %w", err)
		}
		if len(sender) != IdentityIDBytes || bytes.Equal(sender, recipientIdentityID) || !validMessageID(messageID) ||
			acceptedAt < 0 || expiresAt <= acceptedAt || expiresAt-acceptedAt > MaxMessageTTLSeconds ||
			expiresAt <= nowUnixSeconds || ciphertextSize <= 0 || ciphertextSize > MaxCiphertextBytes ||
			len(encoded) == 0 || len(encoded) > MaxEnvelopeBytes {
			return nil, ErrMailboxCorrupt
		}
		decoded, err := DecodeEnvelope(encoded)
		if err != nil {
			return nil, ErrMailboxCorrupt
		}
		canonical, err := EncodeEnvelope(decoded)
		if err != nil || !bytes.Equal(canonical, encoded) ||
			!bytes.Equal(decoded.SenderIdentityID, sender) ||
			!bytes.Equal(decoded.RecipientIdentityID, recipientIdentityID) ||
			!bytes.Equal(decoded.MessageID, messageID) ||
			decoded.ExpiresAtUnixSeconds != expiresAt ||
			len(decoded.Ciphertext) != ciphertextSize {
			return nil, ErrMailboxCorrupt
		}
		if err := ValidateEnvelopeAt(decoded, nowUnixSeconds); err != nil {
			return nil, ErrMailboxCorrupt
		}
		out = append(out, MailboxDelivery{
			SenderIdentityID:     bytes.Clone(sender),
			RecipientIdentityID:  bytes.Clone(recipientIdentityID),
			MessageID:            bytes.Clone(messageID),
			ExpiresAtUnixSeconds: expiresAt,
			EncodedEnvelope:      bytes.Clone(encoded),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate mailbox messages: %w", err)
	}
	return out, nil
}

func (s *SQLiteMailboxStore) AckMailbox(ctx context.Context, recipientIdentityID, senderIdentityID, messageID []byte) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("mailbox store is unavailable")
	}
	if len(recipientIdentityID) != IdentityIDBytes || len(senderIdentityID) != IdentityIDBytes || bytes.Equal(recipientIdentityID, senderIdentityID) || !validMessageID(messageID) {
		return false, ErrMailboxRejected
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.db.ExecContext(ctx, `
DELETE FROM mailbox_messages
WHERE recipient_identity_id = ? AND sender_identity_id = ? AND message_id = ?`, recipientIdentityID, senderIdentityID, messageID)
	if err != nil {
		return false, fmt.Errorf("delete acknowledged mailbox message: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read mailbox ack result: %w", err)
	}
	return rows == 1, nil
}

func (s *SQLiteMailboxStore) PruneExpired(ctx context.Context, now time.Time) (int64, error) {
	if s == nil || s.db == nil || now.Unix() < 0 {
		return 0, errors.New("mailbox cleanup input is invalid")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin mailbox cleanup: %w", err)
	}
	defer tx.Rollback()
	removed, err := pruneExpiredMailboxTx(ctx, tx, now.UTC().Unix(), MaxMailboxCleanupBatch)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit mailbox cleanup: %w", err)
	}
	return removed, nil
}

func validateMailboxRecord(record MailboxRecord) error {
	if record.AcceptedAtUnixSeconds < 0 || len(record.EncodedEnvelope) == 0 || len(record.EncodedEnvelope) > MaxEnvelopeBytes {
		return ErrMailboxRejected
	}
	if err := ValidateEnvelopeAt(record.Envelope, record.AcceptedAtUnixSeconds); err != nil {
		return ErrMailboxRejected
	}
	canonical, err := EncodeEnvelope(record.Envelope)
	if err != nil || !bytes.Equal(canonical, record.EncodedEnvelope) {
		return ErrMailboxRejected
	}
	return nil
}

func checkMailboxCapacityTx(ctx context.Context, tx *sql.Tx, senderIdentityID, recipientIdentityID []byte, newBytes int64) error {
	recipientCount, recipientBytes, err := mailboxUsageTx(ctx, tx, "recipient_identity_id", recipientIdentityID)
	if err != nil {
		return err
	}
	senderCount, senderBytes, err := mailboxUsageTx(ctx, tx, "sender_identity_id", senderIdentityID)
	if err != nil {
		return err
	}
	var globalCount, globalBytes int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(SUM(length(encoded_envelope)), 0) FROM mailbox_messages").Scan(&globalCount, &globalBytes); err != nil {
		return fmt.Errorf("read global mailbox usage: %w", err)
	}
	if recipientCount >= MaxMailboxMessagesPerRecipient || recipientBytes+newBytes > MaxMailboxBytesPerRecipient ||
		senderCount >= MaxMailboxMessagesPerSender || senderBytes+newBytes > MaxMailboxBytesPerSender ||
		globalCount >= MaxMailboxMessagesGlobal || globalBytes+newBytes > MaxMailboxBytesGlobal {
		return ErrMailboxCapacity
	}
	return nil
}

func mailboxUsageTx(ctx context.Context, tx *sql.Tx, column string, identityID []byte) (int64, int64, error) {
	if column != "recipient_identity_id" && column != "sender_identity_id" {
		return 0, 0, errors.New("invalid mailbox usage column")
	}
	query := "SELECT COUNT(*), COALESCE(SUM(length(encoded_envelope)), 0) FROM mailbox_messages WHERE " + column + " = ?"
	var count, bytesUsed int64
	if err := tx.QueryRowContext(ctx, query, identityID).Scan(&count, &bytesUsed); err != nil {
		return 0, 0, fmt.Errorf("read mailbox usage: %w", err)
	}
	return count, bytesUsed, nil
}

func pruneExpiredMailboxTx(ctx context.Context, tx *sql.Tx, nowUnixSeconds int64, limit int) (int64, error) {
	if nowUnixSeconds < 0 || limit <= 0 || limit > MaxMailboxCleanupBatch {
		return 0, errors.New("mailbox cleanup bound is invalid")
	}
	result, err := tx.ExecContext(ctx, `
DELETE FROM mailbox_messages
WHERE mailbox_id IN (
    SELECT mailbox_id
    FROM mailbox_messages
    WHERE expires_at <= ?
    ORDER BY expires_at, mailbox_id
    LIMIT ?
)`, nowUnixSeconds, limit)
	if err != nil {
		return 0, fmt.Errorf("prune expired mailbox messages: %w", err)
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read mailbox cleanup result: %w", err)
	}
	return removed, nil
}
