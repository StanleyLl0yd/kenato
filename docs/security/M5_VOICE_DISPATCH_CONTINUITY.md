# M5 durable effect claim continuity — isolated KDL1 research

Status: **DRAFT / UNWIRED / NOT PHYSICAL / NOT A RELEASE FIX**.
Trackers: #87 P13/P14, #116, #168, #171. The production voice effect
runner does not exist. M5 OPEN, M6 prohibited.

## Security finding and bounded candidate

The existing `VoiceSignalReplayJournal` persists `dispatchClaimed` under
a public SHA-256 checksum. Restoring an old authentic unclaimed snapshot or
recomputing that checksum permits a second claim in the journal. Passing
regressions in #171 deliberately demonstrate the flaw, not remediation.

`VoiceDispatchContinuityLedger` adds a distinct **KDL1 research boundary**:
given an already authenticated permit, it commits the SHA-256 digest of
owner/peer/message/call/kind/envelope-hash under one dedicated, per-commit
Keystore epoch. A claim only returns true after a new AtomicFile-like write,
read-back verification, retirement of the previous independent key, and final
namespace/file verification. An older restored file no longer matches
the remaining key; a forged plaintext journal cannot alter the independent
ledger. Missing, extra, stale or unavailable keys and ambiguous writes fail
closed. The bounded 1024-entry ledger deliberately has NO pruning; a full
ledger must refuse future effects rather than discard replay protection.

The Kotlin code has **injected JVM fake** epoch keys/backing only. No
real Android Keystore adapter or native audio; no production factory,
no new permission, no migration, no server/TURN change. It is not wired
into the existing journal or effect runner. JVM concurrency checks only
serialize one app process and cannot prove multi-process durability.

## Requirements before a real at-most-once guarantee

1. The M2/M3/WSS durable owner must authenticate the exact semantic event
   independently of attacker-controlled journal fields; identify the exact
   peer/call, verify expiry and signed consent, and take one serialized claim
   before **any** ring/send/media effect. The gate does not authenticate its
   caller; a fabricated new permit could otherwise be claimed as a distinct
   ID. Do not use it as a stand-alone authorization mechanism.
2. The existing journal, encrypted semantic store, M3 pending handoff, and
   effect ledger require an explicitly reviewed cross-store commit/recovery
   protocol. An epoch-protected independent ledger alone does not make
   multiple files one transaction, nor does it prevent duplicate M3 ratchet
   advances or premature ACK.
3. Define one-way migration and upgrade/downgrade from unprotected
   historical journals. Never automatically trust previously unclaimed
   effects after migration; preserve M4 text without silent identity reset.
4. Provide a **new, isolated** Android Keystore namespace, real bounded
   no-backup AtomicFile adapter and secure destructive key-first recovery.
   Do not reuse M3 KAE2 or M5 consent KCE2 aliases.
5. Physical Android 10/13/14+ P13/P14 tests must verify process kill,
   reboot, low storage, pre/post-commit crash, alias retirement, file
   restoration and two-phone exactly-correlated effects. Verify latency,
   hardware-backed properties and lifecycle/resource cleanup.
6. External security review, source/vendor lineage, native CVEs and
   repository-wide audit remain required before approving #87/#88/#116.

**Neither this Draft nor green JVM CI means exactly-once audio is working.**
The only claim established by the synthetic tests is resistance to the
specified file-only rollback adversary assuming a faithful, non-rolled-back
Keystore epoch namespace and successful durable atomic writes.