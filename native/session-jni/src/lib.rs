//! Minimal JNI boundary for the Kenato M3 vodozemac session engine.
//!
//! All Java inputs are bounded before copying, native failures become a pending
//! `IllegalStateException`, and secret pickle-key buffers are zeroized after
//! crossing the JNI copy boundary. The Android layer remains responsible for
//! wrapping each fresh pickle key and durably committing advanced snapshots
//! before releasing ciphertext or plaintext.

use std::{
    fmt,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
};

use jni::{
    objects::{JByteArray, JClass},
    sys::{jbyteArray, jint},
    JNIEnv,
};
use kenato_session_engine::{
    create_account, create_inbound_session, create_outbound_session, decrypt_session,
    encrypt_session, generate_account_one_time_keys, inspect_account, mark_account_keys_published,
    AccountMutation, AccountPublicState, DecryptResult, EncryptResult, EncryptedSnapshot,
    EngineError, InboundSessionResult, OutboundSessionResult, MAX_ACCOUNT_SNAPSHOT_BYTES,
    MAX_OLM_MESSAGE_BYTES, MAX_PLAINTEXT_BYTES, MAX_SESSION_SNAPSHOT_BYTES, PICKLE_KEY_BYTES,
};
use zeroize::Zeroize;

const BRIDGE_VERSION: u32 = 1;
const OLM_PUBLIC_KEY_BYTES: usize = 32;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_SESSION_ID_BYTES: usize = 128;

#[derive(Debug)]
enum BridgeError {
    InvalidInput(&'static str),
    Jni(jni::errors::Error),
    Engine(EngineError),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(reason) => write!(formatter, "invalid JNI input: {reason}"),
            Self::Jni(error) => write!(formatter, "JNI failure: {error}"),
            Self::Engine(error) => write!(formatter, "native session engine failure: {error}"),
        }
    }
}

impl From<jni::errors::Error> for BridgeError {
    fn from(error: jni::errors::Error) -> Self {
        Self::Jni(error)
    }
}

impl From<EngineError> for BridgeError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn run_bridge<'local, F>(mut env: JNIEnv<'local>, operation: F) -> jbyteArray
where
    F: FnOnce(&mut JNIEnv<'local>) -> Result<Vec<u8>, BridgeError>,
{
    let result = catch_unwind(AssertUnwindSafe(|| operation(&mut env)));
    match result {
        Ok(Ok(mut response)) => {
            if response.is_empty() || response.len() > MAX_RESPONSE_BYTES {
                response.zeroize();
                return throw_bridge_error(&mut env, "native session response size is invalid");
            }
            let java_response = env.byte_array_from_slice(&response);
            response.zeroize();
            match java_response {
                Ok(array) => array.into_raw(),
                Err(error) => throw_bridge_error(
                    &mut env,
                    &format!("JNI response allocation failed: {error}"),
                ),
            }
        }
        Ok(Err(error)) => throw_bridge_error(&mut env, &error.to_string()),
        Err(_) => throw_bridge_error(&mut env, "native session engine panicked"),
    }
}

fn throw_bridge_error(env: &mut JNIEnv<'_>, message: &str) -> jbyteArray {
    let _ = env.throw_new("java/lang/IllegalStateException", message);
    ptr::null_mut()
}

fn read_bytes(
    env: &JNIEnv<'_>,
    value: &JByteArray<'_>,
    maximum: usize,
    allow_empty: bool,
) -> Result<Vec<u8>, BridgeError> {
    let length = usize::try_from(env.get_array_length(value)?).map_err(|_| {
        BridgeError::InvalidInput("byte-array length cannot be represented as usize")
    })?;
    if length > maximum || (!allow_empty && length == 0) {
        return Err(BridgeError::InvalidInput(
            "byte-array length is out of bounds",
        ));
    }
    let bytes = env.convert_byte_array(value)?;
    if bytes.len() != length {
        return Err(BridgeError::InvalidInput(
            "byte-array length changed during JNI copy",
        ));
    }
    Ok(bytes)
}

fn read_exact(
    env: &JNIEnv<'_>,
    value: &JByteArray<'_>,
    expected: usize,
) -> Result<Vec<u8>, BridgeError> {
    let bytes = read_bytes(env, value, expected, false)?;
    if bytes.len() != expected {
        return Err(BridgeError::InvalidInput("byte-array length is not exact"));
    }
    Ok(bytes)
}

fn read_secret_pickle_key(
    env: &JNIEnv<'_>,
    value: &JByteArray<'_>,
) -> Result<SecretBytes, BridgeError> {
    Ok(SecretBytes(read_exact(env, value, PICKLE_KEY_BYTES)?))
}

fn read_snapshot_text(
    env: &JNIEnv<'_>,
    value: &JByteArray<'_>,
    maximum: usize,
) -> Result<String, BridgeError> {
    let bytes = read_bytes(env, value, maximum, false)?;
    String::from_utf8(bytes)
        .map_err(|_| BridgeError::InvalidInput("encrypted snapshot is not UTF-8"))
}

fn begin_response() -> Vec<u8> {
    let mut output = Vec::with_capacity(512);
    write_u32(&mut output, BRIDGE_VERSION);
    output
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), BridgeError> {
    let length = u32::try_from(value.len())
        .map_err(|_| BridgeError::InvalidInput("native response field is too large"))?;
    write_u32(output, length);
    output.extend_from_slice(value);
    Ok(())
}

fn write_string(output: &mut Vec<u8>, value: &str) -> Result<(), BridgeError> {
    if value.is_empty() || value.len() > MAX_SESSION_ID_BYTES {
        return Err(BridgeError::InvalidInput(
            "native session id size is invalid",
        ));
    }
    write_bytes(output, value.as_bytes())
}

fn write_snapshot(output: &mut Vec<u8>, snapshot: EncryptedSnapshot) -> Result<(), BridgeError> {
    let (ciphertext, mut pickle_key) = snapshot.into_parts();
    write_bytes(output, ciphertext.as_bytes())?;
    output.extend_from_slice(&pickle_key);
    pickle_key.zeroize();
    Ok(())
}

fn write_public_account(
    output: &mut Vec<u8>,
    public: &AccountPublicState,
) -> Result<(), BridgeError> {
    output.extend_from_slice(&public.identity.ed25519);
    output.extend_from_slice(&public.identity.curve25519);
    let count = u32::try_from(public.unpublished_one_time_keys.len())
        .map_err(|_| BridgeError::InvalidInput("too many unpublished one-time keys"))?;
    write_u32(output, count);
    public
        .unpublished_one_time_keys
        .iter()
        .for_each(|key| output.extend_from_slice(key));
    let stored_count = u32::try_from(public.stored_one_time_key_count)
        .map_err(|_| BridgeError::InvalidInput("stored one-time-key count is too large"))?;
    write_u32(output, stored_count);
    Ok(())
}

fn encode_account_mutation(result: AccountMutation) -> Result<Vec<u8>, BridgeError> {
    let mut output = begin_response();
    write_snapshot(&mut output, result.snapshot)?;
    write_public_account(&mut output, &result.public)?;
    Ok(output)
}

fn encode_public_account(public: &AccountPublicState) -> Result<Vec<u8>, BridgeError> {
    let mut output = begin_response();
    write_public_account(&mut output, public)?;
    Ok(output)
}

fn encode_snapshot(snapshot: EncryptedSnapshot) -> Result<Vec<u8>, BridgeError> {
    let mut output = begin_response();
    write_snapshot(&mut output, snapshot)?;
    Ok(output)
}

fn encode_outbound(result: OutboundSessionResult) -> Result<Vec<u8>, BridgeError> {
    let mut output = begin_response();
    write_snapshot(&mut output, result.session)?;
    write_string(&mut output, &result.session_id)?;
    write_u32(&mut output, result.initial_message.message_type);
    write_bytes(&mut output, &result.initial_message.ciphertext)?;
    Ok(output)
}

fn encode_inbound(result: InboundSessionResult) -> Result<Vec<u8>, BridgeError> {
    let mut output = begin_response();
    write_snapshot(&mut output, result.account)?;
    write_snapshot(&mut output, result.session)?;
    write_string(&mut output, &result.session_id)?;
    write_bytes(&mut output, &result.plaintext)?;
    Ok(output)
}

fn encode_encrypt(result: EncryptResult) -> Result<Vec<u8>, BridgeError> {
    let mut output = begin_response();
    write_snapshot(&mut output, result.session)?;
    write_u32(&mut output, result.message.message_type);
    write_bytes(&mut output, &result.message.ciphertext)?;
    Ok(output)
}

fn encode_decrypt(result: DecryptResult) -> Result<Vec<u8>, BridgeError> {
    let mut output = begin_response();
    write_snapshot(&mut output, result.session)?;
    write_bytes(&mut output, &result.plaintext)?;
    Ok(output)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_com_sl_kenato_session_NativeSessionBridge_createAccount(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jbyteArray {
    run_bridge(env, |_env| encode_account_mutation(create_account()?))
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_com_sl_kenato_session_NativeSessionBridge_inspectAccount(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    account_ciphertext: JByteArray<'_>,
    account_pickle_key: JByteArray<'_>,
) -> jbyteArray {
    run_bridge(env, |env| {
        let ciphertext = read_snapshot_text(env, &account_ciphertext, MAX_ACCOUNT_SNAPSHOT_BYTES)?;
        let pickle_key = read_secret_pickle_key(env, &account_pickle_key)?;
        encode_public_account(&inspect_account(&ciphertext, pickle_key.as_slice())?)
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_com_sl_kenato_session_NativeSessionBridge_markAccountKeysPublished(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    account_ciphertext: JByteArray<'_>,
    account_pickle_key: JByteArray<'_>,
) -> jbyteArray {
    run_bridge(env, |env| {
        let ciphertext = read_snapshot_text(env, &account_ciphertext, MAX_ACCOUNT_SNAPSHOT_BYTES)?;
        let pickle_key = read_secret_pickle_key(env, &account_pickle_key)?;
        encode_snapshot(mark_account_keys_published(
            &ciphertext,
            pickle_key.as_slice(),
        )?)
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_com_sl_kenato_session_NativeSessionBridge_generateAccountOneTimeKeys(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    account_ciphertext: JByteArray<'_>,
    account_pickle_key: JByteArray<'_>,
    count: jint,
) -> jbyteArray {
    run_bridge(env, |env| {
        let count = usize::try_from(count)
            .map_err(|_| BridgeError::InvalidInput("one-time-key count is negative"))?;
        let ciphertext = read_snapshot_text(env, &account_ciphertext, MAX_ACCOUNT_SNAPSHOT_BYTES)?;
        let pickle_key = read_secret_pickle_key(env, &account_pickle_key)?;
        encode_account_mutation(generate_account_one_time_keys(
            &ciphertext,
            pickle_key.as_slice(),
            count,
        )?)
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_com_sl_kenato_session_NativeSessionBridge_createOutboundSession(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    account_ciphertext: JByteArray<'_>,
    account_pickle_key: JByteArray<'_>,
    peer_curve25519_identity_key: JByteArray<'_>,
    peer_one_time_key: JByteArray<'_>,
    initial_plaintext: JByteArray<'_>,
) -> jbyteArray {
    run_bridge(env, |env| {
        let ciphertext = read_snapshot_text(env, &account_ciphertext, MAX_ACCOUNT_SNAPSHOT_BYTES)?;
        let pickle_key = read_secret_pickle_key(env, &account_pickle_key)?;
        let peer_identity = read_exact(env, &peer_curve25519_identity_key, OLM_PUBLIC_KEY_BYTES)?;
        let peer_one_time_key = read_exact(env, &peer_one_time_key, OLM_PUBLIC_KEY_BYTES)?;
        let plaintext = read_bytes(env, &initial_plaintext, MAX_PLAINTEXT_BYTES, true)?;
        encode_outbound(create_outbound_session(
            &ciphertext,
            pickle_key.as_slice(),
            &peer_identity,
            &peer_one_time_key,
            &plaintext,
        )?)
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_com_sl_kenato_session_NativeSessionBridge_createInboundSession(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    account_ciphertext: JByteArray<'_>,
    account_pickle_key: JByteArray<'_>,
    expected_peer_curve25519_identity_key: JByteArray<'_>,
    message_type: jint,
    olm_message: JByteArray<'_>,
) -> jbyteArray {
    run_bridge(env, |env| {
        let message_type = u32::try_from(message_type)
            .map_err(|_| BridgeError::InvalidInput("Olm message type is negative"))?;
        let ciphertext = read_snapshot_text(env, &account_ciphertext, MAX_ACCOUNT_SNAPSHOT_BYTES)?;
        let pickle_key = read_secret_pickle_key(env, &account_pickle_key)?;
        let peer_identity = read_exact(
            env,
            &expected_peer_curve25519_identity_key,
            OLM_PUBLIC_KEY_BYTES,
        )?;
        let message = read_bytes(env, &olm_message, MAX_OLM_MESSAGE_BYTES, false)?;
        encode_inbound(create_inbound_session(
            &ciphertext,
            pickle_key.as_slice(),
            &peer_identity,
            message_type,
            &message,
        )?)
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_com_sl_kenato_session_NativeSessionBridge_encryptSession(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    session_ciphertext: JByteArray<'_>,
    session_pickle_key: JByteArray<'_>,
    plaintext: JByteArray<'_>,
) -> jbyteArray {
    run_bridge(env, |env| {
        let ciphertext = read_snapshot_text(env, &session_ciphertext, MAX_SESSION_SNAPSHOT_BYTES)?;
        let pickle_key = read_secret_pickle_key(env, &session_pickle_key)?;
        let plaintext = read_bytes(env, &plaintext, MAX_PLAINTEXT_BYTES, true)?;
        encode_encrypt(encrypt_session(
            &ciphertext,
            pickle_key.as_slice(),
            &plaintext,
        )?)
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn Java_com_sl_kenato_session_NativeSessionBridge_decryptSession(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    session_ciphertext: JByteArray<'_>,
    session_pickle_key: JByteArray<'_>,
    message_type: jint,
    olm_message: JByteArray<'_>,
) -> jbyteArray {
    run_bridge(env, |env| {
        let message_type = u32::try_from(message_type)
            .map_err(|_| BridgeError::InvalidInput("Olm message type is negative"))?;
        let ciphertext = read_snapshot_text(env, &session_ciphertext, MAX_SESSION_SNAPSHOT_BYTES)?;
        let pickle_key = read_secret_pickle_key(env, &session_pickle_key)?;
        let message = read_bytes(env, &olm_message, MAX_OLM_MESSAGE_BYTES, false)?;
        encode_decrypt(decrypt_session(
            &ciphertext,
            pickle_key.as_slice(),
            message_type,
            &message,
        )?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_response_is_versioned_and_bounded() -> Result<(), BridgeError> {
        let response = encode_account_mutation(create_account()?)?;
        assert!(response.len() <= MAX_RESPONSE_BYTES);
        assert_eq!(&response[..4], &BRIDGE_VERSION.to_be_bytes());
        Ok(())
    }

    #[test]
    fn bridge_rejects_unbounded_session_ids() {
        let mut output = begin_response();
        let session_id = "x".repeat(MAX_SESSION_ID_BYTES + 1);
        assert!(matches!(
            write_string(&mut output, &session_id),
            Err(BridgeError::InvalidInput(_))
        ));
    }
}
