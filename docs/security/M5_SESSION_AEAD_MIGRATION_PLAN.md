# M5 M3 state-at-rest migration and rollback decision record

Status: **DRAFT / NOT APPROVED / NOT ENABLED**
Trackers: #116 (Android activation), #87 (security and physical acceptance), #118 (isolated AEAD wrapper).

## Security and product decision

M3 persists native ratchet snapshots and a bounded crypto-coupled messaging
handoff. An outbound M5 v2 handoff can temporarily contain plaintext SDP/ICE
(private IP address and media setup metadata). The legacy app-private
`noBackupFilesDir/kenato_session_v1.state` is protected by Android's sandbox
but **not** by whole-state file encryption. Native Olm pickle wrapping does
not encrypt all serialized handoff fields. This is a local-device disclosure
risk, independent from server-side E2EE.

The isolated `EncryptedSessionStateStore` is a candidate AES-256-GCM wrapper
using a *separate*, nonexportable Keystore alias and a versioned `KSAE`
envelope. **There is no production factory opt-in in this PR.** Its backing
`AtomicFileSessionStateStore` must explicitly use
`EncryptedSessionStateStore.MAX_PERSISTED_BYTES`; the default remains the
old strict plaintext bound for ordinary M4 installations.

### Allowed transitions (proposed; not approved for release)

| Existing file | Keystore | Candidate read behavior | Security outcome |
| --- | --- | --- | --- |
| Missing | none | No state; no migration | Normal fresh setup only through the repository's existing identity flow |
| Canonical `KNS3` legacy | creatable | Validate full canonical state; atomically encrypt and commit before returning any state | One-way upgrade |
| Canonical `KNS3` legacy | unavailable / write fails | Throw; preserve file; never allow the session or ACK to proceed | Fail closed |
| Valid `KSAE` | original alias intact | Authenticate GCM and canonical state; never rewrite legacy plaintext | Protected steady state |
| `KSAE` | missing/invalidated or wrong alias | Throw; do not silently create replacement key or a new M3 account | Destructive identity recovery only with separate explicit confirmation |
| Unknown/corrupt/truncated/oversized | any | Throw; do not parse as fallback legacy state | Fail closed |
| Existing `KSAE` then older APK | old APK cannot parse | Require update to supporting release; **no plaintext downgrade** | Roll-forward-only policy |

Protected-state replacement has a separate fail-closed invariant:
`EncryptedSessionStateStore.write` authenticates and decodes an existing
`KSAE` snapshot **before** encrypting replacement bytes. An invalidated or
lost alias cannot create a fresh key and overwrite inaccessible ratchet or
pending handoff state merely because a caller invokes `write` without
invoking `read` first. Unknown and corrupt prior formats similarly block
replacement until explicit identity recovery. JVM regression tests cover
key rotation, modified ciphertext and invalid file version. The
cipher also receives an explicit key-creation policy for each write:
a pre-existing `KSAE` MUST encrypt using only the existing alias, so alias
loss **between** old-state authentication and replacement cannot silently
generate a different key. Only first-write or canonical `KNS3` migration
may create an alias. This does not prove Android Keystore device behavior
or rollback resistance.

**No automatic downgrade or rollback to `KNS3` is allowed.** A version
rollback after migration would make plaintext SDP/ICE reappear and risks M3
ratchet replay. Current older APKs cannot read `KSAE` and may become unable
to send messages until updated. Before activating, users need a clear
compatibility policy, upgrade/recovery UX and a demonstrated procedure to
roll **forward** to the supported app, never to copy plaintext into backup.

### Destructive identity recovery ordering (isolated proposal)

The candidate `clear()` invalidates its dedicated Android Keystore alias
**before** deleting the protected AtomicFile. A successful key invalidation
must leave any restored old KSAE ciphertext unreadable, even when file
deletion fails, process death interrupts recovery or old backup bytes return.
If alias deletion fails, the file is left unchanged and the operation fails.
The JVM cipher fixture models irreversible deletion and tests both partial
failure directions and ciphertext restore; Android device proof is still
mandatory. This is a fail-closed local recovery invariant, **not general
cryptographic monotonicity**: replay of older valid KSAE while the original
alias is still present *before* destructive recovery remains unresolved.

### Concrete rollback counterexample and required decision

The JVM counterexample `olderAuthenticSnapshotCanStillRollbackStateBeforeAliasInvalidation`
now demonstrates the failure without tampering with AES-GCM: write canonical M3
snapshot A, write newer snapshot B containing a pending outbound voice handoff
using the *same still-valid* dedicated Keystore key, restore the authentic
ciphertext A, and observe that the store accepts A and loses B's handoff. Both
ciphertexts pass authentication. **The passing regression reproduces an attack;
it is not security acceptance.** This is unsafe for a stateful E2EE ratchet.

**Gate decision:** no production M5 voice handoff, M3 AEAD factory migration
or release until the implementation has an independently reviewed continuity
strategy that can reject restored *older valid snapshots*, not just corrupt
ones. Android Keystore AES-GCM with an unchanged alias, app-private counters,
app-private secondary files, timestamps and AtomicFile alone do not provide
such a guarantee against rollback of all mutable app files. Possible
countermeasures must be prototyped and failure-tested; examples include a
hardware-backed non-rollbackable trust anchor where available or a correctly
serialized per-commit key evolution/retirement protocol with fail-closed
interrupted-write recovery. No universal Android 10+ support or performance
claim is made for either option. Hardware/device matrix and backward
compatibility are mandatory.

**Platform support constraint (Android SDK):** StrongBox can be requested on
API 28+ but is optional per device, resource-constrained and not itself a
monotonic M3 snapshot counter. Android Keystore limited-use keys are exposed
on newer Android versions and may be enforced by software on unsupported
hardware. Therefore neither a universal StrongBox dependency nor a
software-enforced usage counter can satisfy the Android 10+ rollback
threat model. References:
- https://developer.android.com/privacy-and-security/keystore
- https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder

Until that decision is supported by actual Android 10/13/14+ evidence, keep
the isolated wrapper Draft and **do not** turn it on in the production session
repository, irrespective of JVM CI success.

### Candidate no-server continuity protocol (isolated prototype; NOT enabled)

For an app-data-file rollback adversary *without permission to mutate the app's
Android Keystore aliases*, a conservative candidate is a **new Keystore alias
per durable ratchet-state commit**, never a reused long-lived alias. Each
canonical encrypted snapshot must carry an authenticated random epoch/alias
identifier. Before reading or writing, enumerate the dedicated key namespace
and reject any absent, extra or mismatched epoch. To commit a new state:
serialize the single M3 writer; create a fresh alias; encrypt under it; atomically
replace the snapshot; retire the prior alias; verify only the new alias remains
before reporting a successful commit.

| Crash / attacker-restored snapshot | Keystore aliases | Required behavior |
| --- | --- | --- |
| Before creating next alias; old file | old only | Old state may continue; no acknowledged newer commit |
| After creating next alias; old file | old + new | **FAIL CLOSED**; cannot infer whether newer state committed |
| After disk replacement; new file | old + new | **FAIL CLOSED** until a separately authenticated recovery decision |
| After retirement; new file | new only | Read the new state |
| After retirement; attacker restores old authentic file | new only | Reject; old matching alias no longer exists |
| File deleted/restored but residual alias(s) exist | any | Reject, never silently create a fresh identity |
| Key deletion fails or key namespace is ambiguous | multiple/unknown | Reject; do not ACK, decrypt or transmit |

**Important cost:** key generation and removal on *every ratchet-advancing
write* may make foreground messages impractically slow; AndroidKeyStore
performance and crash-induced loss of availability require physical measurement.
The transition window is intentionally fail-closed, which can force explicit
identity recovery after power loss. A working protocol must separately handle
canonical legacy KNS3 migration, authenticated rollback of a previously used
epoch, process restarts, and no unacknowledged ratchet reuse. It also needs an
audited threat boundary for malicious code running as the app UID, compromised
hardware/OS Keystore and whole-device rollback; these threats are **not
solved** merely by deleting an alias.

This is **not** an approval or implementation order. Prototype and adversarial
JVM tests must precede an instrumented Keystore benchmark; use it only if
it meets bounded latency, durability, Android 10/13/14+ support and user
recovery requirements. If not, a different trustworthy continuity mechanism
or architectural removal of live sensitive M3 handoffs is required. No
release gate is relaxed.

## Isolated epoch-bound continuity prototype (JVM, not Android acceptance)

The draft #118 branch now contains `EpochBoundSessionStateStore` and
`EpochBoundSessionStateStoreTest`, **separate from** the existing `KSAE` AEAD
candidate and all production factories. The proposed `KAE2` envelope
authenticates a dedicated 32-character epoch identifier as AES-GCM AAD.
The `SessionEpochKeyBackend` interface is an *unimplemented platform boundary*:
the JVM test fixture uses ordinary in-memory AES-GCM keys and a simulated
atomic disk. A separate `AndroidKeystoreSessionEpochKeyBackend` implementation
now supports an instrumented acceptance path using a dedicated AES-GCM key
namespace, but has **not** been exercised on any Android device or emulator.
It does NOT attest to Android Keystore durability, alias semantics or speed.

The proof-of-concept serializes operations within one instance and uses a
fresh epoch key per state write. An existing snapshot is authenticated with
an exactly matching singleton alias namespace before mutation. After creating
the new key, the candidate persists ciphertext, verifies the disk result,
retires the previous key, checks the singleton namespace and reads back the
committed value before returning success. Unexpected aliases, missing files
with residual keys, key deletion failures, ambiguous AtomicFile outcomes and
restored old ciphertext are **fail-closed**, not silently repaired. Implicit
`clear()` and `KNS3` migration intentionally remain unimplemented.

This testable design addresses the *specific adversary who can restore app
files but cannot access or roll back Keystore aliases* in its **successfully
completed** commits. It makes no guarantees against app-UID compromise,
whole-device/Keystore rollback, other processes or a compromised OS.
Interruption after new alias creation can make the identity unavailable;
the prototype does not solve recovery or liveness. A JVM unit test accepting
the older authentic original `KSAE` snapshot is retained as the distinct,
unresolved existing-wrapper counterexample.

**Required before any activation or approval:** prove trustworthy
namespace enumeration and irreversible alias retirement on Android 10/13/14+
hardware; audit hardware-backed versus software-backed keys, reboot/power loss,
AtomicFile backup recovery, and concurrent process interactions; benchmark
per-message Keystore generation/deletion; design a user-confirmed destructive
identity recovery and migration from both `KNS3` and `KSAE`. The JVM fixture is only a fault-injection protocol model, not physical evidence;
the uninvoked Android backend class is not physical evidence either.
No voice, microphone, WebRTC or migration activation follows from it.

## Remaining design/security blockers before activation

1. Confirm Android 10 and Android 13 (minimum), plus an Android 14+ device,
   hardware or emulator Keystore behavior on real app installs. Exercise
   process death before/after AtomicFile write/finishWrite and backup
   restoration. Capture exact app/OS build and file-magic outcomes.
2. Test a real previously published installation with pending M3 outbound
   handoffs, failed migration writes, low storage, ciphertext tamper, lost
   Keystore alias and explicit identity recovery. No UI or worker may ACK
   or decrypt on migration failure.
3. Define rollback/update UX for older installed APKs, without silent
   identity loss, ratchet rollback or exported recovery secrets. Require
   deliberate user confirmation for destructive recovery.
4. Review concurrency: the production M3 repository must use exactly one
   shared durable store and synchronization boundary across contact/consent,
   inbound WSS, offline recovery and outbound voice staging. A second
   repository instance must not race migration or overwrite a new record.
5. Evaluate Android Auto Backup and device-to-device exclusions for file
   and Keystore alias; re-evaluate interrupted restore. Verify no SDP/ICE
   or raw ciphertext is logged, indexed or exposed to crash reporting.
6. Confirm whether corrupt/rolled-back legacy state can be restored after
   an upgrade by Android AtomicFile backup recovery or by an attacker with
   app-private file write access. AES-GCM proves authenticity, **not
   monotonicity or rollback protection**. Do not claim anti-rollback.
7. Complete #87 whole-repository security review and physical two-phone
   tests before enabling voice or publishing a voice test APK.

## Merge and release rules

An isolated cryptographic wrapper can be audited with Android/JVM CI, but
CI on GitHub runners **does not prove physical Keystore compatibility**,
rollback UX, or safe operation on a currently installed phone. Keep #118
in Draft until its own acceptance criteria, migration decision, and
physical-device evidence are reviewed. No direct WebRTC or third-party
STUN/TURN activation, no backend changes and no test release follow from
this document.
