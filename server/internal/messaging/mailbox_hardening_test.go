package messaging

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteMailboxRejectsCorruptAcceptanceWindowOnRead(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	store := openTestMailboxStore(t, ctx, filepath.Join(t.TempDir(), "mailbox.db"), now)
	defer store.Close()

	sender := testBytes(1, IdentityIDBytes)
	recipient := testBytes(40, IdentityIDBytes)
	messageID := testBytes(90, MessageIDBytes)
	envelope := testEnvelope(sender, recipient, messageID, now.Unix()+60)
	if _, err := store.PutMailbox(ctx, mailboxRecord(t, envelope, now.Unix())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	corruptAcceptedAt := envelope.ExpiresAtUnixSeconds - MaxMessageTTLSeconds - 1
	if _, err := store.db.ExecContext(ctx, "UPDATE mailbox_messages SET accepted_at = ?", corruptAcceptedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListMailbox(ctx, recipient, now.Unix(), 1); !errors.Is(err, ErrMailboxCorrupt) {
		t.Fatalf("corrupt acceptance window error=%v", err)
	}
}
