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

## Android 10+ Keystore/AtomicFile acceptance adapters (dormant)

Two Android-only classes are now available for a separately approved *probe*:
`AndroidKeystoreVoiceConsentEpochAcceptanceKeys` and
`AndroidVoiceConsentEpochAcceptanceBacking`. Both require an explicit random
128-bit hex probe ID and have dedicated test-only aliases/file names; neither
can access the active KCS1 file or the M3 epoch namespace. No Android factory
constructs either. They are compiled during Android CI, **not executed on a
physical device**. No Android instrumentation harness, ABI/JNI acceptance,
restart/kill/reboot measurements or existing-user migration is claimed.

An eventual physical test harness must allocate a fresh unpredictable probe ID,
install an **independent diagnostic package** and tear down only its own aliases
and file after each test. Report exact APK SHA and observed Keystore security
level without identifying device serials or exposing consent state. Before a
release-capable implementation, this probe-only namespace must be replaced by
an independently reviewed production namespace and an explicit KCS1-to-KCE2
migration/recovery transaction; a passing synthetic or device probe does not
by itself resolve P23.

## Standalone instrumentation build (not yet executed)

The `m5ConsentProbe` build type is a separate app identity
(`com.sl.kenato.m5consentprobe`), with INTERNET permission removed.
The Android CI job compiles five test-only methods and rejects diagnostic APKs
requesting network or microphone access. It does not install, execute, upload
or publish diagnostic APKs. A device test requires independent APK provenance
and owner-approved physical P23 protocol; process kill/reboot, upgrade, real
migration and two-phone audio are not covered. No existing KCS1 user consent
is modified by this separate instrumentation build.

## Single-process multi-adapter rotation serialization

An independent source review found the candidate's `@Synchronized` lock was
per instance: two adapters pointing to the same KCE2 file and Keystore alias
namespace could interleave distinct epoch creations and write/retire steps.
The isolated candidate now protects authenticated reads and entire commits
with a shared process-local monitor, in addition to per-instance locking.
A concurrent eight-adapter JVM regression checks successful serialized writes
and exactly one live epoch after all commits. This prevents accidental
multi-adapter rotation overlap **within one process only**; cross-process,
crash-consistency, Android Keystore and production migration are NOT solved.
