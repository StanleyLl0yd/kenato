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

**No automatic downgrade or rollback to `KNS3` is allowed.** A version
rollback after migration would make plaintext SDP/ICE reappear and risks M3
ratchet replay. Current older APKs cannot read `KSAE` and may become unable
to send messages until updated. Before activating, users need a clear
compatibility policy, upgrade/recovery UX and a demonstrated procedure to
roll **forward** to the supported app, never to copy plaintext into backup.

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
