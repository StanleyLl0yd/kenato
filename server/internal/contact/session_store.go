package contact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"
)

func (s *SQLiteStore) PublishSessionBootstrap(ctx context.Context, record SessionBootstrapPublicationRecord) (uint64, uint64, error) {
	if err := validateSessionPublicationRecord(record); err != nil {
		return 0, 0, err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin session bootstrap publication: %w", err)
	}
	defer tx.Rollback()

	if err := requireIdentityTx(ctx, tx, record.Bundle.IdentityID); err != nil {
		return 0, 0, err
	}

	var existingGeneration int64
	var existingRevision int64
	var existingMaxPreKeyID int64
	var existingHash []byte
	var existingBundle []byte
	err = tx.QueryRowContext(ctx, `
SELECT account_generation, publication_revision, max_prekey_id_seen, payload_hash, bundle
FROM session_bootstraps WHERE identity_id = ?`, record.Bundle.IdentityID).Scan(
		&existingGeneration,
		&existingRevision,
		&existingMaxPreKeyID,
		&existingHash,
		&existingBundle,
	)
	if errors.Is(err, sql.ErrNoRows) {
		if err := insertInitialSessionBootstrapTx(ctx, tx, record); err != nil {
			return 0, 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, 0, fmt.Errorf("commit initial session bootstrap publication: %w", err)
		}
		return record.Bundle.AccountGeneration, record.Bundle.PublicationRevision, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("read session bootstrap publication: %w", err)
	}

	oldGeneration := uint64(existingGeneration)
	oldRevision := uint64(existingRevision)
	newGeneration := record.Bundle.AccountGeneration
	newRevision := record.Bundle.PublicationRevision

	switch {
	case newGeneration < oldGeneration:
		return 0, 0, ErrSessionConflict
	case newGeneration == oldGeneration:
		if newRevision < oldRevision {
			return 0, 0, ErrSessionConflict
		}
		if newRevision == oldRevision {
			if len(existingHash) == sha256.Size && bytes.Equal(existingHash, record.PayloadHash[:]) {
				if err := tx.Commit(); err != nil {
					return 0, 0, fmt.Errorf("commit idempotent session bootstrap publication: %w", err)
				}
				return newGeneration, newRevision, nil
			}
			return 0, 0, ErrSessionConflict
		}

		existing, err := DecodeSessionBootstrapBundle(existingBundle)
		if err != nil {
			return 0, 0, fmt.Errorf("stored session bootstrap is invalid: %w", err)
		}
		if !bytes.Equal(existing.OlmEd25519IdentityKey, record.Bundle.OlmEd25519IdentityKey) ||
			!bytes.Equal(existing.OlmCurve25519IdentityKey, record.Bundle.OlmCurve25519IdentityKey) {
			return 0, 0, ErrSessionConflict
		}
		maxSeen, err := reconcileSessionPreKeysTx(ctx, tx, record.Bundle, uint64(existingMaxPreKeyID))
		if err != nil {
			return 0, 0, err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE session_bootstraps
SET publication_revision = ?, max_prekey_id_seen = ?, payload_hash = ?, bundle = ?
WHERE identity_id = ? AND account_generation = ? AND publication_revision = ?`,
			int64(newRevision),
			int64(maxSeen),
			record.PayloadHash[:],
			record.EncodedBundle,
			record.Bundle.IdentityID,
			existingGeneration,
			existingRevision,
		); err != nil {
			return 0, 0, fmt.Errorf("update session bootstrap publication: %w", err)
		}

	case newGeneration > oldGeneration:
		if oldGeneration == math.MaxInt64 || newGeneration != oldGeneration+1 || newRevision != 1 {
			return 0, 0, ErrSessionConflict
		}
		// Only a creator account rollover invalidates a reservation, because the
		// reserved OTK belongs to that creator generation. A redeemer rollover
		// does not consume another creator OTK: submit/claim already snapshot and
		// authenticate the redeemer generation independently.
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM session_reservations WHERE creator_identity_id = ?",
			record.Bundle.IdentityID,
		); err != nil {
			return 0, 0, fmt.Errorf("retire old-generation creator session reservations: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM session_one_time_prekeys WHERE identity_id = ?", record.Bundle.IdentityID); err != nil {
			return 0, 0, fmt.Errorf("retire old-generation session prekeys: %w", err)
		}
		maxSeen := record.Bundle.OneTimePreKeys[len(record.Bundle.OneTimePreKeys)-1].ID
		if _, err := tx.ExecContext(ctx, `
UPDATE session_bootstraps
SET account_generation = ?, publication_revision = ?, max_prekey_id_seen = ?, payload_hash = ?, bundle = ?
WHERE identity_id = ? AND account_generation = ?`,
			int64(newGeneration),
			int64(newRevision),
			int64(maxSeen),
			record.PayloadHash[:],
			record.EncodedBundle,
			record.Bundle.IdentityID,
			existingGeneration,
		); err != nil {
			return 0, 0, fmt.Errorf("replace session bootstrap generation: %w", err)
		}
		if err := insertAvailableSessionPreKeysTx(ctx, tx, record.Bundle); err != nil {
			return 0, 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit session bootstrap publication: %w", err)
	}
	return newGeneration, newRevision, nil
}

func (s *SQLiteStore) GetSessionBootstrap(ctx context.Context, identityID []byte) (StoredSessionBootstrap, error) {
	if len(identityID) != IdentityIDBytes {
		return StoredSessionBootstrap{}, ErrSessionKeyUnavailable
	}
	var encoded []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT bundle FROM session_bootstraps WHERE identity_id = ?",
		identityID,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredSessionBootstrap{}, ErrSessionKeyUnavailable
	}
	if err != nil {
		return StoredSessionBootstrap{}, fmt.Errorf("read session bootstrap: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > MaxWireMessageBytes {
		return StoredSessionBootstrap{}, fmt.Errorf("stored session bootstrap violates size bound: %w", ErrInvalidSessionBootstrap)
	}
	return StoredSessionBootstrap{EncodedBundle: bytes.Clone(encoded)}, nil
}

func (s *SQLiteStore) ReserveSessionBootstrap(ctx context.Context, record SessionReservationRecord) (StoredSessionReservation, error) {
	if len(record.CreatorIdentityID) != IdentityIDBytes || len(record.RedeemerIdentityID) != IdentityIDBytes || bytes.Equal(record.CreatorIdentityID, record.RedeemerIdentityID) || record.ReservedAt < 0 {
		return StoredSessionReservation{}, ErrInvalidSessionBootstrap
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return StoredSessionReservation{}, fmt.Errorf("begin session reservation: %w", err)
	}
	defer tx.Rollback()

	if err := requireLiveRedeemedInviteTx(ctx, tx, record.TokenHash, record.CreatorIdentityID, record.RedeemerIdentityID, record.ReservedAt); err != nil {
		return StoredSessionReservation{}, err
	}

	var existingCreator []byte
	var existingRedeemer []byte
	var existingBundle []byte
	var existingKeyID int64
	var existingKey []byte
	err = tx.QueryRowContext(ctx, `
SELECT creator_identity_id, redeemer_identity_id, creator_session_bundle,
       creator_one_time_prekey_id, creator_one_time_public_key
FROM session_reservations WHERE token_hash = ?`, record.TokenHash[:]).Scan(
		&existingCreator,
		&existingRedeemer,
		&existingBundle,
		&existingKeyID,
		&existingKey,
	)
	if err == nil {
		if !bytes.Equal(existingCreator, record.CreatorIdentityID) || !bytes.Equal(existingRedeemer, record.RedeemerIdentityID) || existingKeyID <= 0 || len(existingKey) != OlmPublicKeyBytes {
			return StoredSessionReservation{}, ErrSessionConflict
		}
		if err := tx.Commit(); err != nil {
			return StoredSessionReservation{}, fmt.Errorf("commit idempotent session reservation: %w", err)
		}
		return StoredSessionReservation{
			CreatorBundle: bytes.Clone(existingBundle),
			CreatorOneTimeKey: SessionOneTimePreKey{
				ID:        uint64(existingKeyID),
				PublicKey: bytes.Clone(existingKey),
			},
		}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return StoredSessionReservation{}, fmt.Errorf("read session reservation: %w", err)
	}

	var generation int64
	var creatorBundle []byte
	if err := tx.QueryRowContext(ctx, `
SELECT account_generation, bundle FROM session_bootstraps WHERE identity_id = ?`,
		record.CreatorIdentityID,
	).Scan(&generation, &creatorBundle); errors.Is(err, sql.ErrNoRows) {
		return StoredSessionReservation{}, ErrSessionKeyUnavailable
	} else if err != nil {
		return StoredSessionReservation{}, fmt.Errorf("read creator session bootstrap: %w", err)
	}
	if generation <= 0 || len(creatorBundle) == 0 || len(creatorBundle) > MaxWireMessageBytes {
		return StoredSessionReservation{}, ErrSessionConflict
	}

	var keyID int64
	var publicKey []byte
	if err := tx.QueryRowContext(ctx, `
SELECT key_id, public_key
FROM session_one_time_prekeys
WHERE identity_id = ? AND account_generation = ?
ORDER BY key_id ASC LIMIT 1`, record.CreatorIdentityID, generation).Scan(&keyID, &publicKey); errors.Is(err, sql.ErrNoRows) {
		return StoredSessionReservation{}, ErrSessionKeyUnavailable
	} else if err != nil {
		return StoredSessionReservation{}, fmt.Errorf("select creator session prekey: %w", err)
	}
	if keyID <= 0 || len(publicKey) != OlmPublicKeyBytes {
		return StoredSessionReservation{}, ErrSessionConflict
	}

	result, err := tx.ExecContext(ctx, `
DELETE FROM session_one_time_prekeys
WHERE identity_id = ? AND account_generation = ? AND key_id = ?`,
		record.CreatorIdentityID,
		generation,
		keyID,
	)
	if err != nil {
		return StoredSessionReservation{}, fmt.Errorf("consume creator session prekey reservation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return StoredSessionReservation{}, ErrSessionKeyUnavailable
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO session_reservations(
    token_hash, creator_identity_id, redeemer_identity_id,
    creator_account_generation, creator_one_time_prekey_id,
    creator_one_time_public_key, creator_session_bundle, reserved_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		record.TokenHash[:],
		record.CreatorIdentityID,
		record.RedeemerIdentityID,
		generation,
		keyID,
		publicKey,
		creatorBundle,
		record.ReservedAt,
	); err != nil {
		return StoredSessionReservation{}, fmt.Errorf("insert session reservation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return StoredSessionReservation{}, fmt.Errorf("commit session reservation: %w", err)
	}
	return StoredSessionReservation{
		CreatorBundle: bytes.Clone(creatorBundle),
		CreatorOneTimeKey: SessionOneTimePreKey{
			ID:        uint64(keyID),
			PublicKey: bytes.Clone(publicKey),
		},
	}, nil
}

func (s *SQLiteStore) SubmitSessionInit(ctx context.Context, record SessionInitRecord) error {
	if err := validateSessionInitRecord(record); err != nil {
		return err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin session init submission: %w", err)
	}
	defer tx.Rollback()

	if err := requireLiveRedeemedInviteTx(ctx, tx, record.TokenHash, record.CreatorIdentityID, record.RedeemerIdentityID, record.SubmittedAt); err != nil {
		return err
	}

	var creatorGeneration int64
	var creatorKeyID int64
	var reservationRedeemer []byte
	if err := tx.QueryRowContext(ctx, `
SELECT creator_account_generation, creator_one_time_prekey_id, redeemer_identity_id
FROM session_reservations WHERE token_hash = ?`, record.TokenHash[:]).Scan(
		&creatorGeneration,
		&creatorKeyID,
		&reservationRedeemer,
	); errors.Is(err, sql.ErrNoRows) {
		return ErrSessionKeyUnavailable
	} else if err != nil {
		return fmt.Errorf("read session reservation for init: %w", err)
	}
	if uint64(creatorGeneration) != record.CreatorAccountGeneration || uint64(creatorKeyID) != record.CreatorOneTimePreKeyID || !bytes.Equal(reservationRedeemer, record.RedeemerIdentityID) {
		return ErrSessionInitConflict
	}

	var existingHash []byte
	err = tx.QueryRowContext(ctx,
		"SELECT submit_payload_hash FROM session_inits WHERE token_hash = ?",
		record.TokenHash[:],
	).Scan(&existingHash)
	if err == nil {
		if len(existingHash) == sha256.Size && bytes.Equal(existingHash, record.SubmitPayloadHash[:]) {
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("commit idempotent session init submission: %w", err)
			}
			return nil
		}
		return ErrSessionInitConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read existing session init: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO session_inits(
    token_hash, redeemer_account_generation, submit_payload_hash,
    olm_message_type, olm_message, submit_signature,
    redeemer_session_bundle, submitted_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		record.TokenHash[:],
		int64(record.RedeemerAccountGeneration),
		record.SubmitPayloadHash[:],
		int64(record.OlmMessageType),
		record.OlmMessage,
		record.SubmitSignature,
		record.RedeemerSessionBundle,
		record.SubmittedAt,
	); err != nil {
		return fmt.Errorf("insert session init: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit session init submission: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ClaimSessionInit(ctx context.Context, record SessionClaimRecord) (StoredSessionClaim, error) {
	if len(record.CreatorIdentityID) != IdentityIDBytes || record.ClaimedAt < 0 {
		return StoredSessionClaim{}, ErrInvalidSessionBootstrap
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return StoredSessionClaim{}, fmt.Errorf("begin session init claim: %w", err)
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
		&creatorID,
		&expiresAt,
		&redeemedAt,
		&redeemerID,
		&redemptionSignature,
	)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !bytes.Equal(creatorID, record.CreatorIdentityID)) {
		return StoredSessionClaim{}, ErrInviteNotFound
	}
	if err != nil {
		return StoredSessionClaim{}, fmt.Errorf("read invite for session claim: %w", err)
	}
	if expiresAt <= record.ClaimedAt {
		if _, deleteErr := tx.ExecContext(ctx, "DELETE FROM invites WHERE token_hash = ?", record.TokenHash[:]); deleteErr != nil {
			return StoredSessionClaim{}, fmt.Errorf("delete expired session invite: %w", deleteErr)
		}
		if err := tx.Commit(); err != nil {
			return StoredSessionClaim{}, fmt.Errorf("commit expired session invite deletion: %w", err)
		}
		return StoredSessionClaim{}, ErrInviteExpired
	}
	if !redeemedAt.Valid || len(redeemerID) != IdentityIDBytes || !validSignature(redemptionSignature) {
		return StoredSessionClaim{}, ErrInviteNotRedeemed
	}

	var creatorGeneration int64
	var creatorKeyID int64
	var creatorPublicKey []byte
	var creatorSessionBundle []byte
	var reservationRedeemer []byte
	if err := tx.QueryRowContext(ctx, `
SELECT creator_account_generation, creator_one_time_prekey_id,
       creator_one_time_public_key, creator_session_bundle, redeemer_identity_id
FROM session_reservations WHERE token_hash = ?`, record.TokenHash[:]).Scan(
		&creatorGeneration,
		&creatorKeyID,
		&creatorPublicKey,
		&creatorSessionBundle,
		&reservationRedeemer,
	); errors.Is(err, sql.ErrNoRows) {
		return StoredSessionClaim{}, ErrSessionInitMissing
	} else if err != nil {
		return StoredSessionClaim{}, fmt.Errorf("read session reservation for claim: %w", err)
	}
	if creatorGeneration <= 0 || creatorKeyID <= 0 || len(creatorPublicKey) != OlmPublicKeyBytes || !bytes.Equal(reservationRedeemer, redeemerID) || len(creatorSessionBundle) == 0 || len(creatorSessionBundle) > MaxWireMessageBytes {
		return StoredSessionClaim{}, ErrSessionInitConflict
	}

	var redeemerGeneration int64
	var olmMessageType int64
	var olmMessage []byte
	var submitSignature []byte
	var redeemerSessionBundle []byte
	if err := tx.QueryRowContext(ctx, `
SELECT redeemer_account_generation, olm_message_type, olm_message,
       submit_signature, redeemer_session_bundle
FROM session_inits WHERE token_hash = ?`, record.TokenHash[:]).Scan(
		&redeemerGeneration,
		&olmMessageType,
		&olmMessage,
		&submitSignature,
		&redeemerSessionBundle,
	); errors.Is(err, sql.ErrNoRows) {
		return StoredSessionClaim{}, ErrSessionInitMissing
	} else if err != nil {
		return StoredSessionClaim{}, fmt.Errorf("read session init for claim: %w", err)
	}
	if redeemerGeneration <= 0 || olmMessageType != int64(OlmMessageTypePreKey) || len(olmMessage) == 0 || len(olmMessage) > MaxSessionCiphertextBytes || !validSignature(submitSignature) || len(redeemerSessionBundle) == 0 || len(redeemerSessionBundle) > MaxWireMessageBytes {
		return StoredSessionClaim{}, ErrSessionInitConflict
	}

	var redeemerIdentityBundle []byte
	if err := tx.QueryRowContext(ctx,
		"SELECT bundle FROM identities WHERE identity_id = ?",
		redeemerID,
	).Scan(&redeemerIdentityBundle); err != nil {
		return StoredSessionClaim{}, fmt.Errorf("read redeemer identity for session claim: %w", err)
	}
	if len(redeemerIdentityBundle) == 0 || len(redeemerIdentityBundle) > MaxWireMessageBytes {
		return StoredSessionClaim{}, ErrSessionInitConflict
	}

	result := StoredSessionClaim{
		RedeemerIdentityBundle:   bytes.Clone(redeemerIdentityBundle),
		RedemptionSignature:      bytes.Clone(redemptionSignature),
		RedeemedAt:               redeemedAt.Int64,
		RedeemerSessionBundle:    bytes.Clone(redeemerSessionBundle),
		CreatorSessionBundle:     bytes.Clone(creatorSessionBundle),
		CreatorOneTimeKey:        SessionOneTimePreKey{ID: uint64(creatorKeyID), PublicKey: bytes.Clone(creatorPublicKey)},
		CreatorAccountGeneration: uint64(creatorGeneration),
		OlmMessageType:           uint32(olmMessageType),
		OlmMessage:               bytes.Clone(olmMessage),
		SubmitSignature:          bytes.Clone(submitSignature),
	}

	deleted, err := tx.ExecContext(ctx,
		"DELETE FROM invites WHERE token_hash = ? AND creator_identity_id = ?",
		record.TokenHash[:],
		record.CreatorIdentityID,
	)
	if err != nil {
		return StoredSessionClaim{}, fmt.Errorf("delete claimed session invite: %w", err)
	}
	rows, err := deleted.RowsAffected()
	if err != nil || rows != 1 {
		return StoredSessionClaim{}, ErrInviteNotFound
	}
	if err := tx.Commit(); err != nil {
		return StoredSessionClaim{}, fmt.Errorf("commit session init claim: %w", err)
	}
	return result, nil
}

func insertInitialSessionBootstrapTx(ctx context.Context, tx *sql.Tx, record SessionBootstrapPublicationRecord) error {
	maxSeen := record.Bundle.OneTimePreKeys[len(record.Bundle.OneTimePreKeys)-1].ID
	if _, err := tx.ExecContext(ctx, `
INSERT INTO session_bootstraps(
    identity_id, account_generation, publication_revision,
    max_prekey_id_seen, payload_hash, bundle
) VALUES(?, ?, ?, ?, ?, ?)`,
		record.Bundle.IdentityID,
		int64(record.Bundle.AccountGeneration),
		int64(record.Bundle.PublicationRevision),
		int64(maxSeen),
		record.PayloadHash[:],
		record.EncodedBundle,
	); err != nil {
		return fmt.Errorf("insert session bootstrap: %w", err)
	}
	return insertAvailableSessionPreKeysTx(ctx, tx, record.Bundle)
}

func insertAvailableSessionPreKeysTx(ctx context.Context, tx *sql.Tx, bundle SessionBootstrapBundle) error {
	for _, key := range bundle.OneTimePreKeys {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO session_one_time_prekeys(identity_id, account_generation, key_id, public_key)
VALUES(?, ?, ?, ?)`,
			bundle.IdentityID,
			int64(bundle.AccountGeneration),
			int64(key.ID),
			key.PublicKey,
		); err != nil {
			return fmt.Errorf("insert session prekey: %w", err)
		}
	}
	return nil
}

func reconcileSessionPreKeysTx(ctx context.Context, tx *sql.Tx, bundle SessionBootstrapBundle, maxSeen uint64) (uint64, error) {
	available, err := loadAvailableSessionPreKeysTx(ctx, tx, bundle.IdentityID, bundle.AccountGeneration)
	if err != nil {
		return 0, err
	}
	reserved, err := loadReservedSessionPreKeysTx(ctx, tx, bundle.IdentityID, bundle.AccountGeneration)
	if err != nil {
		return 0, err
	}

	desired := make(map[uint64][]byte, len(bundle.OneTimePreKeys))
	for _, key := range bundle.OneTimePreKeys {
		desired[key.ID] = key.PublicKey
		switch {
		case available[key.ID] != nil:
			if !bytes.Equal(available[key.ID], key.PublicKey) {
				return 0, ErrSessionConflict
			}
		case reserved[key.ID] != nil:
			if !bytes.Equal(reserved[key.ID], key.PublicKey) {
				return 0, ErrSessionConflict
			}
		case key.ID <= maxSeen:
			return 0, ErrSessionConflict
		default:
			if _, err := tx.ExecContext(ctx, `
INSERT INTO session_one_time_prekeys(identity_id, account_generation, key_id, public_key)
VALUES(?, ?, ?, ?)`,
				bundle.IdentityID,
				int64(bundle.AccountGeneration),
				int64(key.ID),
				key.PublicKey,
			); err != nil {
				return 0, fmt.Errorf("insert replenished session prekey: %w", err)
			}
			if key.ID > maxSeen {
				maxSeen = key.ID
			}
		}
	}

	for id := range available {
		if _, keep := desired[id]; keep {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM session_one_time_prekeys
WHERE identity_id = ? AND account_generation = ? AND key_id = ?`,
			bundle.IdentityID,
			int64(bundle.AccountGeneration),
			int64(id),
		); err != nil {
			return 0, fmt.Errorf("retire omitted session prekey: %w", err)
		}
	}
	return maxSeen, nil
}

func loadAvailableSessionPreKeysTx(ctx context.Context, tx *sql.Tx, identityID []byte, generation uint64) (map[uint64][]byte, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT key_id, public_key FROM session_one_time_prekeys
WHERE identity_id = ? AND account_generation = ?`, identityID, int64(generation))
	if err != nil {
		return nil, fmt.Errorf("list available session prekeys: %w", err)
	}
	defer rows.Close()

	result := make(map[uint64][]byte)
	for rows.Next() {
		var id int64
		var publicKey []byte
		if err := rows.Scan(&id, &publicKey); err != nil {
			return nil, fmt.Errorf("scan available session prekey: %w", err)
		}
		if id <= 0 || len(publicKey) != OlmPublicKeyBytes {
			return nil, ErrSessionConflict
		}
		result[uint64(id)] = bytes.Clone(publicKey)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate available session prekeys: %w", err)
	}
	return result, nil
}

func loadReservedSessionPreKeysTx(ctx context.Context, tx *sql.Tx, identityID []byte, generation uint64) (map[uint64][]byte, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT creator_one_time_prekey_id, creator_one_time_public_key
FROM session_reservations
WHERE creator_identity_id = ? AND creator_account_generation = ?`, identityID, int64(generation))
	if err != nil {
		return nil, fmt.Errorf("list reserved session prekeys: %w", err)
	}
	defer rows.Close()

	result := make(map[uint64][]byte)
	for rows.Next() {
		var id int64
		var publicKey []byte
		if err := rows.Scan(&id, &publicKey); err != nil {
			return nil, fmt.Errorf("scan reserved session prekey: %w", err)
		}
		if id <= 0 || len(publicKey) != OlmPublicKeyBytes {
			return nil, ErrSessionConflict
		}
		result[uint64(id)] = bytes.Clone(publicKey)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reserved session prekeys: %w", err)
	}
	return result, nil
}

func requireLiveRedeemedInviteTx(
	ctx context.Context,
	tx *sql.Tx,
	tokenHash [sha256.Size]byte,
	creatorIdentityID []byte,
	redeemerIdentityID []byte,
	now int64,
) error {
	var creatorID []byte
	var expiresAt int64
	var redeemedAt sql.NullInt64
	var redeemerID []byte
	err := tx.QueryRowContext(ctx, `
SELECT creator_identity_id, expires_at, redeemed_at, redeemer_identity_id
FROM invites WHERE token_hash = ?`, tokenHash[:]).Scan(
		&creatorID,
		&expiresAt,
		&redeemedAt,
		&redeemerID,
	)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !bytes.Equal(creatorID, creatorIdentityID)) {
		return ErrInviteNotFound
	}
	if err != nil {
		return fmt.Errorf("read invite for session bootstrap: %w", err)
	}
	if expiresAt <= now {
		// Do not attempt a delete inside this caller-owned transaction and then
		// return an error: the caller would roll that delete back. Expiry is
		// enforced exactly here; startup/hourly retention cleanup performs the
		// durable delete and cascades reservation/init rows.
		return ErrInviteExpired
	}
	if !redeemedAt.Valid || len(redeemerID) != IdentityIDBytes {
		return ErrInviteNotRedeemed
	}
	if !bytes.Equal(redeemerID, redeemerIdentityID) {
		return ErrSessionConflict
	}
	return nil
}

func validateSessionPublicationRecord(record SessionBootstrapPublicationRecord) error {
	if err := validateSessionBootstrapShape(record.Bundle, true); err != nil {
		return err
	}
	if len(record.EncodedBundle) == 0 || len(record.EncodedBundle) > MaxWireMessageBytes {
		return ErrInvalidSessionBootstrap
	}
	encoded, err := EncodeSessionBootstrapBundle(record.Bundle)
	if err != nil || !bytes.Equal(encoded, record.EncodedBundle) {
		return ErrInvalidSessionBootstrap
	}
	payload, err := SessionBootstrapPayload(record.Bundle)
	if err != nil {
		return ErrInvalidSessionBootstrap
	}
	expectedHash := sha256.Sum256(payload)
	if expectedHash != record.PayloadHash {
		return ErrInvalidSessionBootstrap
	}
	return nil
}

func validateSessionInitRecord(record SessionInitRecord) error {
	if len(record.CreatorIdentityID) != IdentityIDBytes || len(record.RedeemerIdentityID) != IdentityIDBytes || bytes.Equal(record.CreatorIdentityID, record.RedeemerIdentityID) {
		return ErrInvalidSessionBootstrap
	}
	if record.CreatorAccountGeneration == 0 || record.CreatorAccountGeneration > math.MaxInt64 || record.CreatorOneTimePreKeyID == 0 || record.CreatorOneTimePreKeyID > math.MaxInt64 || record.RedeemerAccountGeneration == 0 || record.RedeemerAccountGeneration > math.MaxInt64 || record.SubmittedAt < 0 {
		return ErrInvalidSessionBootstrap
	}
	if record.OlmMessageType != OlmMessageTypePreKey || len(record.OlmMessage) == 0 || len(record.OlmMessage) > MaxSessionCiphertextBytes || !validSignature(record.SubmitSignature) || len(record.RedeemerSessionBundle) == 0 || len(record.RedeemerSessionBundle) > MaxWireMessageBytes {
		return ErrInvalidSessionBootstrap
	}
	return nil
}
