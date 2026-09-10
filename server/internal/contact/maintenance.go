package contact

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// PruneExpiredInvites removes M2 invite relationship metadata whose protocol
// lifetime has ended. Expiry enforcement in redeem/claim remains exact; this
// method bounds how long inaccessible expired rows remain at rest.
func (s *SQLiteStore) PruneExpiredInvites(ctx context.Context, now time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("contact store is unavailable")
	}
	if now.Unix() < 0 {
		return 0, errors.New("invite cleanup time is invalid")
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM invites WHERE expires_at <= ?", now.Unix())
	if err != nil {
		return 0, fmt.Errorf("prune expired invites: %w", err)
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read expired invite cleanup result: %w", err)
	}
	return removed, nil
}
