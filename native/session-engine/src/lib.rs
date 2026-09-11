//! Kenato M3 native session engine core.
//!
//! This crate deliberately exposes a small, bounded state-transition API over
//! vodozemac Olm. Android/JNI code is expected to persist the encrypted
//! snapshots returned by each successful mutation before releasing ciphertext
//! or plaintext to higher layers.

use std::fmt;

use rand::{RngCore, rngs::OsRng};
use vodozemac::{
    Curve25519PublicKey,
    olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle},
};
use zeroize::Zeroize;

/// Initial unpublished Olm one-time keys generated for a fresh M3 account.
pub const INITIAL_ONE_TIME_KEYS: usize = 32;
/// Maximum unpublished one-time keys accepted in one Kenato publication batch.
pub const MAX_ONE_TIME_KEYS_PER_PUBLICATION: usize = 50;
/// Maximum application/control plaintext accepted by the M3 primitive.
pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1024;
/// Maximum encoded Olm message accepted or emitted by the M3 primitive.
pub const MAX_OLM_MESSAGE_BYTES: usize = 96 * 1024;
/// Maximum encrypted serialized account snapshot accepted by the native core.
pub const MAX_ACCOUNT_SNAPSHOT_BYTES: usize = 256 * 1024;
/// Maximum encrypted serialized session snapshot accepted by the native core.
pub const MAX_SESSION_SNAPSHOT_BYTES: usize = 256 * 1024;
/// Exact vodozemac pickle-key size required by the selected engine.
pub const PICKLE_KEY_BYTES: usize = 32;

/// Fail-closed error categories returned by the native session core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineError {
    /// A caller-provided bound or shape was invalid.
    InvalidInput(&'static str),
    /// A Curve25519 public key was not exactly 32 valid bytes.
    InvalidCurve25519Key,
    /// An encrypted account snapshot could not be authenticated/restored.
    InvalidAccountState,
    /// An encrypted session snapshot could not be authenticated/restored.
    InvalidSessionState,
    /// An Olm message type was not one of Kenato's supported values.
    InvalidMessageType,
    /// An Olm message was malformed or could not be decoded.
    InvalidMessage,
    /// Olm session establishment failed.
    SessionEstablishmentFailed,
    /// Olm encryption failed.
    EncryptionFailed,
    /// Olm decryption/authentication failed.
    DecryptionFailed,
    /// Secure operating-system randomness was unavailable.
    RandomnessUnavailable,
    /// The vodozemac account would have discarded an existing one-time key.
    OneTimeKeyCapacityExceeded,
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(reason) => write!(formatter, "invalid input: {reason}"),
            Self::InvalidCurve25519Key => formatter.write_str("invalid Curve25519 public key"),
            Self::InvalidAccountState => formatter.write_str("invalid encrypted account state"),
            Self::InvalidSessionState => formatter.write_str("invalid encrypted session state"),
            Self::InvalidMessageType => formatter.write_str("unsupported Olm message type"),
            Self::InvalidMessage => formatter.write_str("invalid Olm message"),
            Self::SessionEstablishmentFailed => {
                formatter.write_str("Olm session establishment failed")
            }
            Self::EncryptionFailed => formatter.write_str("Olm encryption failed"),
            Self::DecryptionFailed => formatter.write_str("Olm decryption failed"),
            Self::RandomnessUnavailable => formatter.write_str("secure randomness unavailable"),
            Self::OneTimeKeyCapacityExceeded => {
                formatter.write_str("Olm one-time-key capacity would discard an existing key")
            }
        }
    }
}

impl std::error::Error for EngineError {}

/// Public Olm account identity material bound by the existing Kenato P-256 identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountIdentity {
    /// vodozemac account Ed25519 fingerprint public key.
    pub ed25519: [u8; 32],
    /// vodozemac account Curve25519 identity public key.
    pub curve25519: [u8; 32],
}

/// Public, non-secret view of a local vodozemac account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountPublicState {
    /// Stable public identity keys for this account snapshot.
    pub identity: AccountIdentity,
    /// Currently unpublished Curve25519 one-time public keys, canonically sorted.
    pub unpublished_one_time_keys: Vec<[u8; 32]>,
    /// Number of one-time private keys retained by the account.
    pub stored_one_time_key_count: usize,
}

/// Authenticated encrypted vodozemac state paired with its fresh random pickle key.
///
/// The pickle key is secret and is zeroized when this value is dropped. Android
/// must wrap it with the dedicated non-exportable Keystore key before durable
/// storage.
pub struct EncryptedSnapshot {
    ciphertext: String,
    pickle_key: [u8; PICKLE_KEY_BYTES],
}

impl EncryptedSnapshot {
    /// Borrow the authenticated encrypted serialized state.
    pub fn ciphertext(&self) -> &str {
        &self.ciphertext
    }

    /// Borrow the secret 32-byte pickle key.
    pub fn pickle_key(&self) -> &[u8; PICKLE_KEY_BYTES] {
        &self.pickle_key
    }

    /// Consume the snapshot for transfer across the persistence/JNI boundary.
    pub fn into_parts(mut self) -> (String, [u8; PICKLE_KEY_BYTES]) {
        let ciphertext = std::mem::take(&mut self.ciphertext);
        let pickle_key = std::mem::take(&mut self.pickle_key);
        (ciphertext, pickle_key)
    }
}

impl fmt::Debug for EncryptedSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedSnapshot")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("pickle_key", &"[redacted]")
            .finish()
    }
}

impl Drop for EncryptedSnapshot {
    fn drop(&mut self) {
        self.pickle_key.zeroize();
    }
}

/// Result of creating or mutating a local Olm account.
#[derive(Debug)]
pub struct AccountMutation {
    /// Fresh encrypted account snapshot that must replace the previous snapshot atomically.
    pub snapshot: EncryptedSnapshot,
    /// Public account material after the mutation.
    pub public: AccountPublicState,
}

/// Bounded encoded Olm message plus its explicit transport type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionMessage {
    /// `0` for an Olm pre-key message, `1` for an Olm normal message.
    pub message_type: u32,
    /// Opaque encoded Olm frame bytes.
    pub ciphertext: Vec<u8>,
}

/// Result of deterministic initiator-side outbound session creation.
#[derive(Debug)]
pub struct OutboundSessionResult {
    /// Advanced session snapshot after encrypting the initial pre-key control frame.
    pub session: EncryptedSnapshot,
    /// Stable vodozemac session id for consistency checks.
    pub session_id: String,
    /// Initial Olm pre-key frame carrying Kenato's authenticated control plaintext.
    pub initial_message: SessionMessage,
}

/// Result of responder-side inbound session creation.
#[derive(Debug)]
pub struct InboundSessionResult {
    /// Advanced account snapshot after the matching one-time key was consumed.
    pub account: EncryptedSnapshot,
    /// New responder session snapshot after authenticating/decrypting the pre-key frame.
    pub session: EncryptedSnapshot,
    /// Stable vodozemac session id for consistency checks.
    pub session_id: String,
    /// Authenticated plaintext from the initial pre-key frame.
    pub plaintext: Vec<u8>,
}

/// Result of one outbound session encryption mutation.
#[derive(Debug)]
pub struct EncryptResult {
    /// Advanced session snapshot that must be durably committed before sending the message.
    pub session: EncryptedSnapshot,
    /// Opaque Olm frame produced by the successful mutation.
    pub message: SessionMessage,
}

/// Result of one inbound session decryption mutation.
#[derive(Debug)]
pub struct DecryptResult {
    /// Advanced session snapshot that must be durably committed before releasing plaintext.
    pub session: EncryptedSnapshot,
    /// Authenticated plaintext produced by the successful mutation.
    pub plaintext: Vec<u8>,
}

/// Create a fresh vodozemac account with Kenato's fixed initial one-time-key pool.
pub fn create_account() -> Result<AccountMutation, EngineError> {
    let mut account = Account::new();
    let generated = account.generate_one_time_keys(INITIAL_ONE_TIME_KEYS);
    if !generated.removed.is_empty() {
        return Err(EngineError::OneTimeKeyCapacityExceeded);
    }

    let public = public_account_state(&account);
    let snapshot = snapshot_account(&account)?;
    Ok(AccountMutation { snapshot, public })
}

/// Restore and inspect public account material without mutating persisted state.
pub fn inspect_account(
    ciphertext: &str,
    pickle_key: &[u8],
) -> Result<AccountPublicState, EngineError> {
    let account = load_account(ciphertext, pickle_key)?;
    Ok(public_account_state(&account))
}

/// Mark all currently unpublished vodozemac one-time keys as published.
///
/// The returned snapshot must be durably committed only after the matching
/// authenticated public bootstrap publication has succeeded.
pub fn mark_account_keys_published(
    ciphertext: &str,
    pickle_key: &[u8],
) -> Result<EncryptedSnapshot, EngineError> {
    let mut account = load_account(ciphertext, pickle_key)?;
    account.mark_keys_as_published();
    snapshot_account(&account)
}

/// Generate a bounded additional batch of one-time keys without allowing the
/// engine to evict an older retained private key.
pub fn generate_account_one_time_keys(
    ciphertext: &str,
    pickle_key: &[u8],
    count: usize,
) -> Result<AccountMutation, EngineError> {
    if count == 0 || count > MAX_ONE_TIME_KEYS_PER_PUBLICATION {
        return Err(EngineError::InvalidInput(
            "one-time-key generation count is out of bounds",
        ));
    }

    let mut account = load_account(ciphertext, pickle_key)?;
    if account.one_time_keys().len().saturating_add(count) > MAX_ONE_TIME_KEYS_PER_PUBLICATION {
        return Err(EngineError::InvalidInput(
            "total unpublished one-time-key count exceeds the M3 publication bound",
        ));
    }
    let generated = account.generate_one_time_keys(count);
    if !generated.removed.is_empty() {
        return Err(EngineError::OneTimeKeyCapacityExceeded);
    }

    let public = public_account_state(&account);
    let snapshot = snapshot_account(&account)?;
    Ok(AccountMutation { snapshot, public })
}

/// Create the invite-redeemer outbound session and encrypt its initial control plaintext.
///
/// The account itself is not mutated by outbound session creation; only the
/// returned session snapshot advances when the initial pre-key frame is encrypted.
pub fn create_outbound_session(
    account_ciphertext: &str,
    account_pickle_key: &[u8],
    peer_curve25519_identity_key: &[u8],
    peer_one_time_key: &[u8],
    initial_plaintext: &[u8],
) -> Result<OutboundSessionResult, EngineError> {
    check_plaintext(initial_plaintext)?;

    let account = load_account(account_ciphertext, account_pickle_key)?;
    let peer_identity = parse_curve25519(peer_curve25519_identity_key)?;
    let peer_one_time = parse_curve25519(peer_one_time_key)?;

    let mut session = account
        .create_outbound_session(SessionConfig::version_1(), peer_identity, peer_one_time)
        .map_err(|_| EngineError::SessionEstablishmentFailed)?;

    let message = session
        .encrypt(initial_plaintext)
        .map_err(|_| EngineError::EncryptionFailed)?;
    let initial_message = encode_message(&message)?;
    if initial_message.message_type != 0 {
        return Err(EngineError::SessionEstablishmentFailed);
    }

    let session_id = session.session_id();
    let session = snapshot_session(&session)?;
    Ok(OutboundSessionResult {
        session,
        session_id,
        initial_message,
    })
}

/// Create the invite-creator inbound session from an authenticated pre-key frame.
///
/// The returned account and session snapshots form one logical local transaction:
/// Android must commit both before exposing the returned plaintext.
pub fn create_inbound_session(
    account_ciphertext: &str,
    account_pickle_key: &[u8],
    expected_peer_curve25519_identity_key: &[u8],
    message_type: u32,
    olm_message: &[u8],
) -> Result<InboundSessionResult, EngineError> {
    if message_type != 0 {
        return Err(EngineError::InvalidMessageType);
    }

    let decoded = decode_message(message_type, olm_message)?;
    let OlmMessage::PreKey(pre_key_message) = decoded else {
        return Err(EngineError::InvalidMessageType);
    };

    let expected_peer = parse_curve25519(expected_peer_curve25519_identity_key)?;
    let mut account = load_account(account_ciphertext, account_pickle_key)?;
    let result = account
        .create_inbound_session(SessionConfig::version_1(), expected_peer, &pre_key_message)
        .map_err(|_| EngineError::SessionEstablishmentFailed)?;

    if result.plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(EngineError::InvalidInput(
            "decrypted plaintext exceeds the M3 bound",
        ));
    }

    let session_id = result.session.session_id();
    let account = snapshot_account(&account)?;
    let session = snapshot_session(&result.session)?;

    Ok(InboundSessionResult {
        account,
        session,
        session_id,
        plaintext: result.plaintext,
    })
}

/// Encrypt one bounded opaque application payload using an existing Olm session.
///
/// The returned advanced session snapshot must be durably committed before the
/// caller may transmit the returned ciphertext.
pub fn encrypt_session(
    session_ciphertext: &str,
    session_pickle_key: &[u8],
    plaintext: &[u8],
) -> Result<EncryptResult, EngineError> {
    check_plaintext(plaintext)?;
    let mut session = load_session(session_ciphertext, session_pickle_key)?;
    let message = session
        .encrypt(plaintext)
        .map_err(|_| EngineError::EncryptionFailed)?;
    let message = encode_message(&message)?;
    let session = snapshot_session(&session)?;
    Ok(EncryptResult { session, message })
}

/// Decrypt one bounded Olm frame using an existing session.
///
/// The returned advanced session snapshot must be durably committed before the
/// caller may release the returned plaintext to application code.
pub fn decrypt_session(
    session_ciphertext: &str,
    session_pickle_key: &[u8],
    message_type: u32,
    olm_message: &[u8],
) -> Result<DecryptResult, EngineError> {
    let message = decode_message(message_type, olm_message)?;
    let mut session = load_session(session_ciphertext, session_pickle_key)?;
    let plaintext = session
        .decrypt(&message)
        .map_err(|_| EngineError::DecryptionFailed)?;

    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(EngineError::InvalidInput(
            "decrypted plaintext exceeds the M3 bound",
        ));
    }

    let session = snapshot_session(&session)?;
    Ok(DecryptResult { session, plaintext })
}

fn public_account_state(account: &Account) -> AccountPublicState {
    let ed25519 = *account.ed25519_key().as_bytes();
    let curve25519 = account.curve25519_key().to_bytes();
    let mut unpublished_one_time_keys: Vec<[u8; 32]> = account
        .one_time_keys()
        .into_values()
        .map(|key| key.to_bytes())
        .collect();
    unpublished_one_time_keys.sort_unstable();

    AccountPublicState {
        identity: AccountIdentity {
            ed25519,
            curve25519,
        },
        unpublished_one_time_keys,
        stored_one_time_key_count: account.stored_one_time_key_count(),
    }
}

fn check_plaintext(plaintext: &[u8]) -> Result<(), EngineError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        Err(EngineError::InvalidInput("plaintext exceeds the M3 bound"))
    } else {
        Ok(())
    }
}

fn parse_curve25519(bytes: &[u8]) -> Result<Curve25519PublicKey, EngineError> {
    Curve25519PublicKey::from_slice(bytes).map_err(|_| EngineError::InvalidCurve25519Key)
}

fn encode_message(message: &OlmMessage) -> Result<SessionMessage, EngineError> {
    let (message_type, ciphertext) = message.to_parts();
    if ciphertext.is_empty() || ciphertext.len() > MAX_OLM_MESSAGE_BYTES {
        return Err(EngineError::InvalidInput(
            "encoded Olm message is out of bounds",
        ));
    }

    let message_type = match message_type {
        0 => 0,
        1 => 1,
        _ => return Err(EngineError::InvalidMessageType),
    };
    Ok(SessionMessage {
        message_type,
        ciphertext,
    })
}

fn decode_message(message_type: u32, ciphertext: &[u8]) -> Result<OlmMessage, EngineError> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_OLM_MESSAGE_BYTES {
        return Err(EngineError::InvalidInput(
            "encoded Olm message is out of bounds",
        ));
    }

    let message_type = match message_type {
        0 => 0,
        1 => 1,
        _ => return Err(EngineError::InvalidMessageType),
    };

    OlmMessage::from_parts(message_type, ciphertext).map_err(|_| EngineError::InvalidMessage)
}

fn load_account(ciphertext: &str, pickle_key: &[u8]) -> Result<Account, EngineError> {
    check_snapshot(
        ciphertext,
        MAX_ACCOUNT_SNAPSHOT_BYTES,
        "account snapshot is out of bounds",
    )?;
    let mut key = copy_pickle_key(pickle_key)?;
    let result = AccountPickle::from_encrypted(ciphertext, &key)
        .map(Account::from_pickle)
        .map_err(|_| EngineError::InvalidAccountState);
    key.zeroize();
    result
}

fn load_session(ciphertext: &str, pickle_key: &[u8]) -> Result<Session, EngineError> {
    check_snapshot(
        ciphertext,
        MAX_SESSION_SNAPSHOT_BYTES,
        "session snapshot is out of bounds",
    )?;
    let mut key = copy_pickle_key(pickle_key)?;
    let result = SessionPickle::from_encrypted(ciphertext, &key)
        .map(Session::from_pickle)
        .map_err(|_| EngineError::InvalidSessionState);
    key.zeroize();
    result
}

fn snapshot_account(account: &Account) -> Result<EncryptedSnapshot, EngineError> {
    let mut pickle_key = random_pickle_key()?;
    let ciphertext = account.pickle().encrypt(&pickle_key);
    if ciphertext.is_empty() || ciphertext.len() > MAX_ACCOUNT_SNAPSHOT_BYTES {
        pickle_key.zeroize();
        return Err(EngineError::InvalidAccountState);
    }
    Ok(EncryptedSnapshot {
        ciphertext,
        pickle_key,
    })
}

fn snapshot_session(session: &Session) -> Result<EncryptedSnapshot, EngineError> {
    let mut pickle_key = random_pickle_key()?;
    let ciphertext = session.pickle().encrypt(&pickle_key);
    if ciphertext.is_empty() || ciphertext.len() > MAX_SESSION_SNAPSHOT_BYTES {
        pickle_key.zeroize();
        return Err(EngineError::InvalidSessionState);
    }
    Ok(EncryptedSnapshot {
        ciphertext,
        pickle_key,
    })
}

fn check_snapshot(
    ciphertext: &str,
    maximum: usize,
    reason: &'static str,
) -> Result<(), EngineError> {
    if ciphertext.is_empty() || ciphertext.len() > maximum {
        Err(EngineError::InvalidInput(reason))
    } else {
        Ok(())
    }
}

fn copy_pickle_key(pickle_key: &[u8]) -> Result<[u8; PICKLE_KEY_BYTES], EngineError> {
    if pickle_key.len() != PICKLE_KEY_BYTES {
        return Err(EngineError::InvalidInput(
            "pickle key must be exactly 32 bytes",
        ));
    }
    let mut key = [0u8; PICKLE_KEY_BYTES];
    key.copy_from_slice(pickle_key);
    Ok(key)
}

fn random_pickle_key() -> Result<[u8; PICKLE_KEY_BYTES], EngineError> {
    let mut key = [0u8; PICKLE_KEY_BYTES];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut key)
        .map_err(|_| EngineError::RandomnessUnavailable)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_lifecycle_is_bounded_and_roundtrips() -> Result<(), EngineError> {
        let account = create_account()?;
        assert_eq!(
            account.public.unpublished_one_time_keys.len(),
            INITIAL_ONE_TIME_KEYS
        );
        assert_eq!(
            account.public.stored_one_time_key_count,
            INITIAL_ONE_TIME_KEYS
        );

        let inspected =
            inspect_account(account.snapshot.ciphertext(), account.snapshot.pickle_key())?;
        assert_eq!(inspected, account.public);

        let published = mark_account_keys_published(
            account.snapshot.ciphertext(),
            account.snapshot.pickle_key(),
        )?;
        let inspected = inspect_account(published.ciphertext(), published.pickle_key())?;
        assert!(inspected.unpublished_one_time_keys.is_empty());
        assert_eq!(inspected.stored_one_time_key_count, INITIAL_ONE_TIME_KEYS);

        let replenished =
            generate_account_one_time_keys(published.ciphertext(), published.pickle_key(), 5)?;
        assert_eq!(replenished.public.unpublished_one_time_keys.len(), 5);
        assert_eq!(
            replenished.public.stored_one_time_key_count,
            INITIAL_ONE_TIME_KEYS + 5
        );
        Ok(())
    }

    #[test]
    fn one_time_key_generation_rejects_unbounded_counts() -> Result<(), EngineError> {
        let account = create_account()?;
        let result = generate_account_one_time_keys(
            account.snapshot.ciphertext(),
            account.snapshot.pickle_key(),
            MAX_ONE_TIME_KEYS_PER_PUBLICATION + 1,
        );
        assert!(matches!(result, Err(EngineError::InvalidInput(_))));
        Ok(())
    }

    #[test]
    fn one_time_key_generation_rejects_total_unpublished_overflow() -> Result<(), EngineError> {
        let account = create_account()?;
        let remaining = MAX_ONE_TIME_KEYS_PER_PUBLICATION - INITIAL_ONE_TIME_KEYS;
        let filled = generate_account_one_time_keys(
            account.snapshot.ciphertext(),
            account.snapshot.pickle_key(),
            remaining,
        )?;
        assert_eq!(
            filled.public.unpublished_one_time_keys.len(),
            MAX_ONE_TIME_KEYS_PER_PUBLICATION
        );
        let overflow = generate_account_one_time_keys(
            filled.snapshot.ciphertext(),
            filled.snapshot.pickle_key(),
            1,
        );
        assert!(matches!(overflow, Err(EngineError::InvalidInput(_))));
        Ok(())
    }

    #[test]
    fn outbound_inbound_roundtrip_and_replay_fail_closed() -> Result<(), EngineError> {
        let alice = create_account()?;
        let bob = create_account()?;
        let bob_otk = bob.public.unpublished_one_time_keys[0];

        let outbound = create_outbound_session(
            alice.snapshot.ciphertext(),
            alice.snapshot.pickle_key(),
            &bob.public.identity.curve25519,
            &bob_otk,
            b"kenato-control",
        )?;
        assert_eq!(outbound.initial_message.message_type, 0);

        let inbound = create_inbound_session(
            bob.snapshot.ciphertext(),
            bob.snapshot.pickle_key(),
            &alice.public.identity.curve25519,
            outbound.initial_message.message_type,
            &outbound.initial_message.ciphertext,
        )?;
        assert_eq!(inbound.plaintext, b"kenato-control");
        assert_eq!(outbound.session_id, inbound.session_id);

        let reply = encrypt_session(
            inbound.session.ciphertext(),
            inbound.session.pickle_key(),
            b"reply",
        )?;
        assert_eq!(reply.message.message_type, 1);

        let received = decrypt_session(
            outbound.session.ciphertext(),
            outbound.session.pickle_key(),
            reply.message.message_type,
            &reply.message.ciphertext,
        )?;
        assert_eq!(received.plaintext, b"reply");

        let replay = decrypt_session(
            received.session.ciphertext(),
            received.session.pickle_key(),
            reply.message.message_type,
            &reply.message.ciphertext,
        );
        assert!(matches!(replay, Err(EngineError::DecryptionFailed)));
        Ok(())
    }

    #[test]
    fn out_of_order_messages_use_bounded_engine_skipped_keys() -> Result<(), EngineError> {
        let alice = create_account()?;
        let bob = create_account()?;
        let bob_otk = bob.public.unpublished_one_time_keys[0];

        let outbound = create_outbound_session(
            alice.snapshot.ciphertext(),
            alice.snapshot.pickle_key(),
            &bob.public.identity.curve25519,
            &bob_otk,
            b"control",
        )?;
        let inbound = create_inbound_session(
            bob.snapshot.ciphertext(),
            bob.snapshot.pickle_key(),
            &alice.public.identity.curve25519,
            outbound.initial_message.message_type,
            &outbound.initial_message.ciphertext,
        )?;

        let first = encrypt_session(
            inbound.session.ciphertext(),
            inbound.session.pickle_key(),
            b"one",
        )?;
        let second = encrypt_session(
            first.session.ciphertext(),
            first.session.pickle_key(),
            b"two",
        )?;

        let second_first = decrypt_session(
            outbound.session.ciphertext(),
            outbound.session.pickle_key(),
            second.message.message_type,
            &second.message.ciphertext,
        )?;
        assert_eq!(second_first.plaintext, b"two");

        let first_second = decrypt_session(
            second_first.session.ciphertext(),
            second_first.session.pickle_key(),
            first.message.message_type,
            &first.message.ciphertext,
        )?;
        assert_eq!(first_second.plaintext, b"one");
        Ok(())
    }

    #[test]
    fn corrupted_account_snapshot_fails_closed() -> Result<(), EngineError> {
        let account = create_account()?;
        let mut corrupted = account.snapshot.ciphertext().as_bytes().to_vec();
        if corrupted.is_empty() {
            return Err(EngineError::InvalidAccountState);
        }
        corrupted[0] = if corrupted[0] == b'A' { b'B' } else { b'A' };
        let corrupted =
            String::from_utf8(corrupted).map_err(|_| EngineError::InvalidAccountState)?;

        let result = inspect_account(&corrupted, account.snapshot.pickle_key());
        assert!(matches!(result, Err(EngineError::InvalidAccountState)));
        Ok(())
    }

    #[test]
    fn malformed_and_oversized_inputs_are_rejected_before_engine_use() -> Result<(), EngineError> {
        let account = create_account()?;
        let oversized_plaintext = vec![0u8; MAX_PLAINTEXT_BYTES + 1];
        let oversized = create_outbound_session(
            account.snapshot.ciphertext(),
            account.snapshot.pickle_key(),
            &[1u8; 32],
            &[2u8; 32],
            &oversized_plaintext,
        );
        assert!(matches!(oversized, Err(EngineError::InvalidInput(_))));

        let oversized_message = vec![0u8; MAX_OLM_MESSAGE_BYTES + 1];
        let malformed = decode_message(1, &oversized_message);
        assert!(matches!(malformed, Err(EngineError::InvalidInput(_))));
        assert!(matches!(
            decode_message(2, &[1]),
            Err(EngineError::InvalidMessageType)
        ));
        Ok(())
    }
}
