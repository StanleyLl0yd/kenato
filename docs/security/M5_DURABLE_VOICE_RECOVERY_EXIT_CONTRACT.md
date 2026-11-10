# M5 #116 — durable voice recovery and owner exit contract

Status: **review contract only**. No production owner, voice transport, native media,
microphone, TURN, server change, release or M6 approval. This does not create
a new milestone. Applies to #87 P13/P14/P17/P23 and existing Drafts
#118 (M3 KAE2), #123 (Android factory lease), #170 (M2 consent KCE2),
#174/#175 (KDL1 effect continuity) and #176 (isolated call proposals).

## Ownership boundary before opening any WSS or executing effects

One Android application/service owner must hold the **same** cross-process
storage lease for M1 identity, verified M2 contact + signed, expiring, single-use
voice-v2 capability/revocation, M3 native ratchet and ciphertext handoffs,
M4 WSS recovery/ACK, encrypted M5 semantic events and the KDL1 effect claim.
No Compose component, direct constructor, secondary process, timer or socket
callback may bypass that owner. A process-lifetime file lock provides advisory
**exclusion**, not crash-safe multi-store commit or anti-rollback.

After process death, a new lease holder must validate the local identity,
contact pin, capability epoch, M3 epoch/key namespace, all staged handoffs,
replay/semantic correspondence and the KDL1 key epoch before it may send ACKs,
reconnect voice WSS, or propose effects. Unknown, missing, extra, rolled-back
or contradictory state blocks all voice effects; there is no silent migration
or silent recreation of deleted Keystore aliases. M4 text compatibility
must remain intact.

All input timestamps are a **single owner-captured local clock snapshot**,
not the peer's sent time. This fixes intra-transaction clock divergence but
does not solve device wall-clock rollback or provide a trusted remote clock.

## Required forward-recovery order

1. M3 decrypt/ratchet advancement and the exact authenticated inbound handoff
   must be committed in the **same** M3 atomic state transition. A pending
   handoff is the only source for recovery; never decrypt that ciphertext again.
2. Validate canonical outer envelope and authenticated inner voice signal;
   retain bound owner, peer, message, call, expiry and envelope digest.
3. Commit the AES-GCM semantic record using the identical time snapshot and
   owner-bound AAD. A recovered exact duplicate must be idempotent.
4. Commit the replay receipt, including expiry and exact envelope digest. For
   recovery, the live semantic and replay sets must match one-for-one; any
   extra or missing event denies the **entire** voice ACK plan until repaired
   from the original authenticated M3 handoff.
5. Only then is an ACK *eligible*. The authenticated WSS owner still verifies
   transport/session identity and expiry; this is not permission for a call
   effect. A late/duplicate ACK must not re-run a reducer or native code.
6. Before any reducer/ring/network/media effect, independently revalidate
   current pinned consent, exact peer+call, expiry and current owner generation.
   Commit a one-use KDL1 claim before execution. Uncertain claim or epoch
   retirement **fails closed**, even if the OS lease was released after crash.
7. Actual native/media effects require a separately approved, key-scoped
   effect executor. A persisted claim can provide **at-most-once attempt**;
   it cannot guarantee exactly-once delivery after an external-effect crash.
   Do not automatically retry such an effect on restart. STOP_MEDIA may only
   clean up the exact existing call/handle, including after consent revocation.

## Crash/fault matrix

| Crash or fault point | Required recovery result |
| --- | --- |
| Before M3 atomic ratchet/handoff commit | No voice receipt, ACK or effect; uncertain native output is not replay-authorized |
| After M3 commit, before semantic commit | Recover the exact M3 handoff; no second decrypt; no ACK yet |
| After semantic write, before replay receipt | Semantic-only record blocks the full ACK plan; idempotently import missing replay receipt from the original handoff |
| Replay receipt write refused/uncertain | No ACK; preserve M3 handoff; inspect authenticated stores and retry reconciliation, never accept a forged receipt |
| After matching semantic+replay commits, before ACK send | Exact, still-live ACK may be issued by the authenticated WSS owner; no reducer effect implied |
| After ACK send, before server confirms | Retain bounded idempotent ACK eligibility; duplicated acknowledgement cannot grant another effect |
| After KDL1 claim, before external effect | Treat as consumed; no automatic retry after process death, even if user sees no ring |
| After starting media, before cleanup | Process death invalidates in-memory handles; restart must not resurrect native handles or bypass consent |
| During consent revocation or cross-process start | Durable KCE2 revocation and one owner gate must win before new effect; reject stale queued starts |
| Missing/extra Keystore alias, restored old file or uncertain AtomicFile return | Fail closed; explicit reviewed destructive recovery only, never regenerate active keys |

## Minimum evidence and exit gate

- Synthetic fault injection **between every write/claim/ACK/effect boundary**;
  restoration of an older authentic M3, KCE2, semantic and KDL1 file;
  cross-process writer contention, process kill and restart; corrupted or
  mismatched owner/peer/message/call binding.
- Execute actual Android Keystore/AtomicFile probes on the agreed Android
  versions, with exact APK/hash/device evidence; host JVM tests are not
  physical anti-rollback or JNI assurance.
- Verify signed M2/v2 consent, revocation during call, late and reordered WSS
  callbacks, offline expiry, concurrent sends, busy/glare and denial of
  microphone permission on **two physical phones**.
- Resolve #88 ARM64 real JNI, binary provenance/CVE/license approval;
  #91 owner-authorized OCI rollout; #87 P01–P24; final full repository-wide
  build, tests and security audit before any voice APK/release.
- Until every gate has evidence, keep security PRs Draft, M5 OPEN, M6 closed,
  production WebRTC/microphone/TURN inactive and published v0.0.4 unchanged.

This contract documents the missing integrated owner. An isolated primitive
or a passing synthetic test does not satisfy it.
