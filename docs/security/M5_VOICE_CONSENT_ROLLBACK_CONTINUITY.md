# M5 P23: voice capability consent rollback continuity

Status: **ISOLATED JVM PROPOSAL / NOT A FIX IN PRODUCTION / NOT PHYSICALLY APPROVED**.
Trackers: #87 (P23), #116 (lifecycle), #118 (separate M3 KAE2 experiment).

## Confirmed baseline weakness

The existing v1 capability file has an AES-GCM integrity tag under one persistent
`com.sl.kenato.m5.voice-capability.v1` Keystore alias. `revoke()` rewrites the
file but does not retire that alias. An attacker capable of restoring a prior
authentic app-private encrypted file can restore a previously approved voice
capability despite a successful revoke. The new dedicated baseline JVM test
**deliberately reproduces this failure**, rather than proving anti-rollback.

## KCE2 isolated candidate

`EpochBoundVoiceConsentStore` models a distinct, versioned outer envelope for
already-encrypted M5 consent bytes, with an independent *per-commit* epoch key
namespace and AAD. The existing inner cipher remains conceptually separate.
A successful commit must (1) authenticate the current file under the **only**
present epoch key, (2) create a new independent key, (3) atomically commit and
read back the new protected bytes, (4) retire the old key, and (5) re-authenticate
the result with exactly one key remaining. Missing files with orphaned keys,
stale files with retired keys, additional aliases and uncertain writes fail
closed. No auto-key-recovery, implicit KCS1 migration or key deletion exists.

The proposed Kotlin class is **unwired** and accepts injected fake backing
and key operations; tests are synthetic and do NOT execute Android Keystore,
AtomicFile, process death, reboot or P23. Current v1 consent format, factory,
M4 messaging, target SDK, microphone and production release remain unchanged.

## Required before considering integration

- Independent security review of file-and-key transaction, Android Keystore
  alias lifecycle, lost-key behavior, crash windows and concurrent processes.
- Separate reviewed Android Keystore backend and larger-capacity no-backup
  AtomicFile adapter; never repurpose the v1 file or M3 key namespace.
- One-way migration decision for existing KCS1 positive grants. No silent
  grandfathering or automatic acceptance: explicit fresh consent may be needed.
- Explicit destructive identity recovery that invalidates both old and new
  aliases before clearing data, with rollback and error evidence.
- Android 10/13/14+ hardware observations and actual P23 restore/revoke/
  restart, upgrade and key-durability fault testing.
- Full M5 repository audit and lifecycle/effect runner admission gate.
  A file-only adversary model does NOT cover compromised app UID, OS, Keystore,
  backups of Keystore state or hostile runtime hooks.

**Do not merge as acceptance or enable voice based on passing JVM tests.**
