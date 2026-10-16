# M5 capability-consent Keystore replacement gate

Status: isolated security hardening proposal (#116, PR #127), not live-call activation.

## Decision and exact boundary

The Android M5 voice capability consent file is a dedicated no-backup
AtomicFile, encrypted using a separate Android Keystore AES-256-GCM alias.
There are two distinct encryption cases:

- **No existing file:** a new challenge may create the key for the first
  ciphertext; it never grants voice support without explicit signed consent.
- **Authenticated existing file:** challenge rotation, proof confirmation and
  revocation must encrypt using an **already existing key**. They must not
  create a fresh alias when the previous alias disappears between read and
  write. Keystore loss must fail closed without replacing the stored bytes.

The repository decides from an authenticated file read whether replacement
requires an existing key. The production cipher enforces the decision at
encryption time. JVM fault injection invalidates the alias after decrypt and
before replacement for each mutation, asserting no overwrite and no new alias.
This is **not** a guarantee that the Keystore cannot later be invalidated.

## Explicit limitations

- AES-GCM authentication rejects tampering but **cannot detect rollback of
  a previously valid encrypted grant**. An attacker who can restore old
  app-private files may be able to restore previously revoked consent if the
  corresponding key remains usable. A security decision on that threat and
  anti-rollback evidence are still required; never call file encryption
  non-rollbackable.
- The existing process-level consent lock (#126) does not cover another
  Android process, independently mutated M2 pins, M3 ratchet, M4 history or
  a future effect runner. Every outbound effect must revalidate at execution.
- JVM key-loss tests are not Android Keystore hardware/device evidence.
  Test process death, key invalidation/rotation, AtomicFile failure and
  recovery on Android 10, 13 and 14+ before approval.
- Do not enable microphone, WebRTC AAR, network voice, new servers,
  TURN or an M5 release. #118, #123, #88 and #87 retain their own gates.
