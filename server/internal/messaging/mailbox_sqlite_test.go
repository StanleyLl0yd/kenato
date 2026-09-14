package messaging

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSQLiteMailboxExactRetryConflictRestartAndAck(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	path := filepath.Join(t.TempDir(), "mailbox.db")
	store := openTestMailboxStore(t, ctx, path, now)
	sender := testBytes(1, IdentityIDBytes)
	recipient := testBytes(40, IdentityIDBytes)
	messageID := testBytes(90, MessageIDBytes)
	record := mailboxRecord(t, testEnvelope(sender, recipient, messageID, now.Unix()+60), now.Unix())
	inserted, err := store.PutMailbox(ctx, record)
	if err != nil || !inserted {
		t.Fatalf("first put inserted=%v err=%v", inserted, err)
	}
	inserted, err = store.PutMailbox(ctx, record)
	if err != nil || inserted {
		t.Fatalf("exact retry inserted=%v err=%v", inserted, err)
	}
	otherRecipient := testBytes(140, IdentityIDBytes)
	conflict := mailboxRecord(t, testEnvelope(sender, otherRecipient, messageID, now.Unix()+60), now.Unix())
	if _, err := store.PutMailbox(ctx, conflict); !errors.Is(err, ErrMailboxRejected) {
		t.Fatalf("conflicting retry error=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openTestMailboxStore(t, ctx, path, now)
	defer store.Close()
	deliveries, err := store.ListMailbox(ctx, recipient, now.Unix(), MaxMailboxDeliveryPage)
	if err != nil || len(deliveries) != 1 || !bytes.Equal(deliveries[0].EncodedEnvelope, record.EncodedEnvelope) {
		t.Fatalf("restart delivery count=%d err=%v", len(deliveries), err)
	}
	deleted, err := store.AckMailbox(ctx, recipient, sender, messageID)
	if err != nil || !deleted {
		t.Fatalf("ack deleted=%v err=%v", deleted, err)
	}
	deleted, err = store.AckMailbox(ctx, recipient, sender, messageID)
	if err != nil || deleted {
		t.Fatalf("duplicate ack deleted=%v err=%v", deleted, err)
	}
}

func TestSQLiteMailboxRejectsNonCanonicalRecordBeforePersistence(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	store := openTestMailboxStore(t, ctx, filepath.Join(t.TempDir(), "mailbox.db"), now)
	defer store.Close()
	envelope := testEnvelope(testBytes(1, IdentityIDBytes), testBytes(40, IdentityIDBytes), testBytes(90, MessageIDBytes), now.Unix()+60)
	record := mailboxRecord(t, envelope, now.Unix())
	record.EncodedEnvelope = append(record.EncodedEnvelope, 0x38, 0x01)
	if _, err := store.PutMailbox(ctx, record); !errors.Is(err, ErrMailboxRejected) {
		t.Fatalf("noncanonical record error=%v", err)
	}
}

func TestSQLiteMailboxAckIsBoundToRecipientAndSender(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	store := openTestMailboxStore(t, ctx, filepath.Join(t.TempDir(), "mailbox.db"), now)
	defer store.Close()
	sender := testBytes(1, IdentityIDBytes)
	otherSender := testBytes(80, IdentityIDBytes)
	recipient := testBytes(40, IdentityIDBytes)
	messageID := testBytes(120, MessageIDBytes)
	_, err := store.PutMailbox(ctx, mailboxRecord(t, testEnvelope(sender, recipient, messageID, now.Unix()+60), now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.AckMailbox(ctx, recipient, otherSender, messageID); err != nil || deleted {
		t.Fatalf("wrong-sender ack deleted=%v err=%v", deleted, err)
	}
	if deleted, err := store.AckMailbox(ctx, otherSender, sender, messageID); err != nil || deleted {
		t.Fatalf("wrong-recipient ack deleted=%v err=%v", deleted, err)
	}
	deliveries, err := store.ListMailbox(ctx, recipient, now.Unix(), 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("message disappeared after mismatched ack: count=%d err=%v", len(deliveries), err)
	}
}

func TestSQLiteMailboxExactExpiryAndCleanupBatchBound(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	store := openTestMailboxStore(t, ctx, filepath.Join(t.TempDir(), "mailbox.db"), now)
	defer store.Close()

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO mailbox_messages(
    sender_identity_id, recipient_identity_id, message_id,
    accepted_at, expires_at, ciphertext_size, encoded_envelope
) VALUES(?, ?, ?, ?, ?, 1, x'01')`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxMailboxCleanupBatch+1; i++ {
		sender := testBytes(byte(1+(i%2)*16), IdentityIDBytes)
		recipient := testBytes(byte(80+(i%3)*40), IdentityIDBytes)
		if _, err := stmt.ExecContext(ctx, sender, recipient, mailboxMessageID(i), now.Unix(), now.Unix()+1); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			t.Fatalf("insert fixture %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	recipient := testBytes(80, IdentityIDBytes)
	deliveries, err := store.ListMailbox(ctx, recipient, now.Unix()+1, MaxMailboxDeliveryPage)
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("expired messages visible at boundary: count=%d err=%v", len(deliveries), err)
	}
	removed, err := store.PruneExpired(ctx, now.Add(time.Second))
	if err != nil || removed != MaxMailboxCleanupBatch {
		t.Fatalf("first cleanup removed=%d err=%v", removed, err)
	}
	removed, err = store.PruneExpired(ctx, now.Add(time.Second))
	if err != nil || removed != 1 {
		t.Fatalf("second cleanup removed=%d err=%v", removed, err)
	}
}

func TestSQLiteMailboxConcurrentRecipientQuota(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	store := openTestMailboxStore(t, ctx, filepath.Join(t.TempDir(), "mailbox.db"), now)
	defer store.Close()
	sender := testBytes(1, IdentityIDBytes)
	recipient := testBytes(40, IdentityIDBytes)

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxMailboxMessagesPerRecipient-1; i++ {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO mailbox_messages(sender_identity_id, recipient_identity_id, message_id, accepted_at, expires_at, ciphertext_size, encoded_envelope)
VALUES(?, ?, ?, ?, ?, 1, x'01')`, sender, recipient, mailboxMessageID(i), now.Unix(), now.Unix()+60); err != nil {
			_ = tx.Rollback()
			t.Fatalf("fill recipient quota %d: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	records := []MailboxRecord{
		mailboxRecord(t, testEnvelope(sender, recipient, mailboxMessageID(MaxMailboxMessagesPerRecipient-1), now.Unix()+60), now.Unix()),
		mailboxRecord(t, testEnvelope(sender, recipient, mailboxMessageID(MaxMailboxMessagesPerRecipient), now.Unix()+60), now.Unix()),
	}
	var wg sync.WaitGroup
	results := make(chan error, len(records))
	for _, record := range records {
		record := record
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.PutMailbox(ctx, record)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	var successes, capacity int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrMailboxCapacity):
			capacity++
		default:
			t.Fatalf("unexpected concurrent quota error: %v", err)
		}
	}
	if successes != 1 || capacity != 1 {
		t.Fatalf("quota race successes=%d capacity=%d", successes, capacity)
	}
}

func TestSQLiteMailboxRejectsMalformedStoredState(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	store := openTestMailboxStore(t, ctx, filepath.Join(t.TempDir(), "mailbox.db"), now)
	defer store.Close()
	store.db.SetMaxOpenConns(1)
	sender := testBytes(1, IdentityIDBytes)
	recipient := testBytes(40, IdentityIDBytes)
	messageID := testBytes(90, MessageIDBytes)
	_, err := store.PutMailbox(ctx, mailboxRecord(t, testEnvelope(sender, recipient, messageID, now.Unix()+60), now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE mailbox_messages SET ciphertext_size = 0"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListMailbox(ctx, recipient, now.Unix(), 1); !errors.Is(err, ErrMailboxCorrupt) {
		t.Fatalf("malformed stored state error=%v", err)
	}
}

func TestSQLiteMailboxRejectsStoredEnvelopeMetadataMismatch(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	store := openTestMailboxStore(t, ctx, filepath.Join(t.TempDir(), "mailbox.db"), now)
	defer store.Close()
	sender := testBytes(1, IdentityIDBytes)
	recipient := testBytes(40, IdentityIDBytes)
	messageID := testBytes(90, MessageIDBytes)
	_, err := store.PutMailbox(ctx, mailboxRecord(t, testEnvelope(sender, recipient, messageID, now.Unix()+60), now.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	otherSender := testBytes(100, IdentityIDBytes)
	if _, err := store.db.ExecContext(ctx, "UPDATE mailbox_messages SET sender_identity_id = ?", otherSender); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListMailbox(ctx, recipient, now.Unix(), 1); !errors.Is(err, ErrMailboxCorrupt) {
		t.Fatalf("metadata mismatch error=%v", err)
	}
}

func TestSQLiteMailboxSecurityConfigurationAndVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mailbox.db")
	now := time.Unix(2_000_000_000, 0).UTC()
	store := openTestMailboxStore(t, ctx, path, now)
	defer store.Close()
	var version, synchronous int
	if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != mailboxSQLiteSchemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	if err := store.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		t.Fatalf("synchronous=%d err=%v", synchronous, err)
	}
	var journalMode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil || journalMode != "wal" {
		t.Fatalf("journal_mode=%q err=%v", journalMode, err)
	}
	matches, err := filepath.Glob(path + "*")
	if err != nil || len(matches) == 0 {
		t.Fatalf("mailbox sqlite artifacts missing: %v", err)
	}
	for _, name := range matches {
		info, err := os.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("mailbox sqlite artifact %s mode=%v", filepath.Base(name), info.Mode())
		}
	}
}

func TestSQLiteMailboxRejectsNewerSchemaAndSymlinkPath(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "future.db")
	db, err := sql.Open("sqlite", mailboxSQLiteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA user_version = 2"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenSQLiteMailboxStore(ctx, path); err == nil {
		_ = store.Close()
		t.Fatal("newer mailbox schema accepted")
	}

	target := filepath.Join(dir, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "mailbox-link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenSQLiteMailboxStore(ctx, link); err == nil {
		_ = store.Close()
		t.Fatal("symlink mailbox database path accepted")
	}
}

func openTestMailboxStore(t *testing.T, ctx context.Context, path string, now time.Time) *SQLiteMailboxStore {
	t.Helper()
	store, err := openSQLiteMailboxStoreWithClock(ctx, path, func() time.Time { return now })
	if err != nil {
		t.Fatalf("open mailbox store: %v", err)
	}
	return store
}

func mailboxRecord(t *testing.T, envelope Envelope, acceptedAt int64) MailboxRecord {
	t.Helper()
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatalf("encode mailbox envelope: %v", err)
	}
	return MailboxRecord{Envelope: envelope, EncodedEnvelope: encoded, AcceptedAtUnixSeconds: acceptedAt}
}

func mailboxMessageID(value int) []byte {
	out := make([]byte, MessageIDBytes)
	binary.BigEndian.PutUint64(out[MessageIDBytes-8:], uint64(value+1))
	return out
}
