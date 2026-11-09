//! Synthetic cross-version Olm continuity evidence for RUSTSEC-2026-0451.
//! Run in an isolated CI temp directory against old and patched native crates.
//! These pickle keys are TEST-ONLY and must never be printed or published.
use kenato_session_engine::{
    EncryptedSnapshot, create_account, create_inbound_session, create_outbound_session,
    decrypt_session, encrypt_session, inspect_account,
};
use std::{env, error::Error, fs, io, path::{Path, PathBuf}};

fn write(root: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    fs::write(root.join(name), value)
}

fn read(root: &Path, name: &str) -> io::Result<Vec<u8>> {
    fs::read(root.join(name))
}

fn save_snapshot(root: &Path, name: &str, snapshot: &EncryptedSnapshot) -> io::Result<()> {
    write(root, &format!("{name}.pickle"), snapshot.ciphertext().as_bytes())?;
    write(root, &format!("{name}.key"), snapshot.pickle_key())
}

fn load_snapshot(root: &Path, name: &str) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    let ciphertext = String::from_utf8(read(root, &format!("{name}.pickle"))?)?;
    let key = read(root, &format!("{name}.key"))?;
    if key.len() != 32 {
        return Err("Invalid synthetic pickle key size".into());
    }
    Ok((ciphertext, key))
}

fn save_message(root: &Path, name: &str, message_type: u32, ciphertext: &[u8]) -> io::Result<()> {
    write(root, &format!("{name}.type"), &message_type.to_be_bytes())?;
    write(root, &format!("{name}.wire"), ciphertext)
}

fn load_message(root: &Path, name: &str) -> Result<(u32, Vec<u8>), Box<dyn Error>> {
    let bytes = read(root, &format!("{name}.type"))?;
    if bytes.len() != 4 {
        return Err("Invalid synthetic message-type size".into());
    }
    let mut encoded = [0u8; 4];
    encoded.copy_from_slice(&bytes);
    Ok((u32::from_be_bytes(encoded), read(root, &format!("{name}.wire"))?))
}

fn create_legacy(root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(root)?;
    let alice = create_account()?;
    let bob = create_account()?;
    let outbound = create_outbound_session(
        alice.snapshot.ciphertext(),
        alice.snapshot.pickle_key(),
        &bob.public.identity.curve25519,
        &bob.public.unpublished_one_time_keys[0],
        b"kenato-versioned-initial-control",
    )?;
    let inbound = create_inbound_session(
        bob.snapshot.ciphertext(), bob.snapshot.pickle_key(),
        &alice.public.identity.curve25519,
        outbound.initial_message.message_type,
        &outbound.initial_message.ciphertext,
    )?;
    assert_eq!(inbound.plaintext, b"kenato-versioned-initial-control");
    assert_eq!(outbound.session_id, inbound.session_id);
    let old_reply = encrypt_session(
        inbound.session.ciphertext(), inbound.session.pickle_key(),
        b"legacy-to-patched-message",
    )?;

    save_snapshot(root, "alice-account", &alice.snapshot)?;
    save_snapshot(root, "bob-account", &inbound.account)?;
    write(root, "alice-id", &alice.public.identity.curve25519)?;
    write(root, "bob-id", &bob.public.identity.curve25519)?;
    save_snapshot(root, "alice-session", &outbound.session)?;
    save_snapshot(root, "bob-session", &old_reply.session)?;
    save_message(root, "legacy-reply", old_reply.message.message_type, &old_reply.message.ciphertext)?;
    Ok(())
}

fn upgrade_with_patched(root: &Path) -> Result<(), Box<dyn Error>> {
    let (alice_account, alice_key) = load_snapshot(root, "alice-account")?;
    let (bob_account, bob_key) = load_snapshot(root, "bob-account")?;
    assert_eq!(
        inspect_account(&alice_account, &alice_key)?.identity.curve25519.as_slice(),
        read(root, "alice-id")?,
    );
    assert_eq!(
        inspect_account(&bob_account, &bob_key)?.identity.curve25519.as_slice(),
        read(root, "bob-id")?,
    );

    let (alice, key) = load_snapshot(root, "alice-session")?;
    let (old_type, old_message) = load_message(root, "legacy-reply")?;
    let received = decrypt_session(&alice, &key, old_type, &old_message)?;
    assert_eq!(received.plaintext, b"legacy-to-patched-message");
    // Migration never needs to replay the same ciphertext after committed advancement.
    assert!(decrypt_session(
        received.session.ciphertext(), received.session.pickle_key(), old_type, &old_message,
    ).is_err());

    let new_reply = encrypt_session(
        received.session.ciphertext(), received.session.pickle_key(),
        b"patched-to-legacy-message",
    )?;
    save_snapshot(root, "alice-patched-session", &new_reply.session)?;
    save_message(root, "patched-reply", new_reply.message.message_type, &new_reply.message.ciphertext)?;
    Ok(())
}

fn accept_patched_from_legacy(root: &Path) -> Result<(), Box<dyn Error>> {
    let (bob, key) = load_snapshot(root, "bob-session")?;
    let (new_type, new_message) = load_message(root, "patched-reply")?;
    let received = decrypt_session(&bob, &key, new_type, &new_message)?;
    assert_eq!(received.plaintext, b"patched-to-legacy-message");
    assert!(decrypt_session(
        received.session.ciphertext(), received.session.pickle_key(), new_type, &new_message,
    ).is_err());
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let operation = env::args().nth(1).ok_or("Expected create, upgrade or legacy")?;
    let root: PathBuf = env::args().nth(2).ok_or("Missing private fixture directory")?.into();
    match operation.as_str() {
        "create" => create_legacy(&root),
        "upgrade" => upgrade_with_patched(&root),
        "legacy" => accept_patched_from_legacy(&root),
        _ => Err("Unsupported compatibility test phase".into()),
    }
}
