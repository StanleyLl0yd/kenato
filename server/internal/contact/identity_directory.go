package contact

import (
	"context"
	"database/sql"
	"fmt"
)

// IdentityExists is an internal directory lookup used only by authenticated
// server components such as M4 routing. It is not exposed as a public API.
func (s *SQLiteStore) IdentityExists(ctx context.Context, identityID []byte) (bool, error) {
	if s == nil || s.db == nil || len(identityID) != IdentityIDBytes {
		return false, nil
	}
	var one int
	err := s.db.QueryRowContext(ctx, "SELECT 1 FROM identities WHERE identity_id = ?", identityID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check internal identity directory: %w", err)
	}
	return one == 1, nil
}
