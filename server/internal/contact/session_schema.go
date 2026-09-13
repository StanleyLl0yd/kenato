package contact

const sessionSQLiteSchema = `
CREATE TABLE IF NOT EXISTS session_bootstraps (
    identity_id BLOB PRIMARY KEY NOT NULL CHECK(length(identity_id) = 32),
    account_generation INTEGER NOT NULL CHECK(account_generation > 0),
    publication_revision INTEGER NOT NULL CHECK(publication_revision > 0),
    max_prekey_id_seen INTEGER NOT NULL CHECK(max_prekey_id_seen > 0),
    payload_hash BLOB NOT NULL CHECK(length(payload_hash) = 32),
    bundle BLOB NOT NULL CHECK(length(bundle) BETWEEN 1 AND 65536),
    FOREIGN KEY (identity_id) REFERENCES identities(identity_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE IF NOT EXISTS session_one_time_prekeys (
    identity_id BLOB NOT NULL CHECK(length(identity_id) = 32),
    account_generation INTEGER NOT NULL CHECK(account_generation > 0),
    key_id INTEGER NOT NULL CHECK(key_id > 0),
    public_key BLOB NOT NULL CHECK(length(public_key) = 32),
    PRIMARY KEY (identity_id, account_generation, key_id),
    UNIQUE (identity_id, account_generation, public_key),
    FOREIGN KEY (identity_id) REFERENCES session_bootstraps(identity_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE IF NOT EXISTS session_reservations (
    token_hash BLOB PRIMARY KEY NOT NULL CHECK(length(token_hash) = 32),
    creator_identity_id BLOB NOT NULL CHECK(length(creator_identity_id) = 32),
    redeemer_identity_id BLOB NOT NULL CHECK(length(redeemer_identity_id) = 32),
    creator_account_generation INTEGER NOT NULL CHECK(creator_account_generation > 0),
    creator_one_time_prekey_id INTEGER NOT NULL CHECK(creator_one_time_prekey_id > 0),
    creator_one_time_public_key BLOB NOT NULL CHECK(length(creator_one_time_public_key) = 32),
    creator_session_bundle BLOB NOT NULL CHECK(length(creator_session_bundle) BETWEEN 1 AND 65536),
    reserved_at INTEGER NOT NULL CHECK(reserved_at >= 0),
    UNIQUE (creator_identity_id, creator_account_generation, creator_one_time_prekey_id),
    FOREIGN KEY (token_hash) REFERENCES invites(token_hash) ON DELETE CASCADE,
    FOREIGN KEY (creator_identity_id) REFERENCES identities(identity_id) ON DELETE CASCADE,
    FOREIGN KEY (redeemer_identity_id) REFERENCES identities(identity_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE IF NOT EXISTS session_inits (
    token_hash BLOB PRIMARY KEY NOT NULL CHECK(length(token_hash) = 32),
    redeemer_account_generation INTEGER NOT NULL CHECK(redeemer_account_generation > 0),
    submit_payload_hash BLOB NOT NULL CHECK(length(submit_payload_hash) = 32),
    olm_message_type INTEGER NOT NULL CHECK(olm_message_type = 0),
    olm_message BLOB NOT NULL CHECK(length(olm_message) BETWEEN 1 AND 98304),
    submit_signature BLOB NOT NULL CHECK(length(submit_signature) BETWEEN 1 AND 2048),
    redeemer_session_bundle BLOB NOT NULL CHECK(length(redeemer_session_bundle) BETWEEN 1 AND 65536),
    submitted_at INTEGER NOT NULL CHECK(submitted_at >= 0),
    FOREIGN KEY (token_hash) REFERENCES session_reservations(token_hash) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER IF NOT EXISTS session_inits_redeemer_generation_guard
BEFORE INSERT ON session_inits
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1
    FROM session_reservations AS reservation
    JOIN session_bootstraps AS bootstrap
      ON bootstrap.identity_id = reservation.redeemer_identity_id
    WHERE reservation.token_hash = NEW.token_hash
      AND bootstrap.account_generation = NEW.redeemer_account_generation
)
BEGIN
    SELECT RAISE(ABORT, 'session init redeemer generation conflict');
END;

CREATE INDEX IF NOT EXISTS session_prekeys_available_idx
    ON session_one_time_prekeys(identity_id, account_generation, key_id);
CREATE INDEX IF NOT EXISTS session_reservations_creator_idx
    ON session_reservations(creator_identity_id, creator_account_generation);
`
