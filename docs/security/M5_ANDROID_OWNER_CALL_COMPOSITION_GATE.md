# M5 Android owner + isolated call proposal integration (research only)

Status: **DRAFT BUILD-COMPATIBILITY PROBE, NOT LIVE VOICE OR APPROVAL**.

This merge-check branch combines the exact files from two independently reviewed,
still-unmerged Draft heads without overwriting common paths:

- #123 `688fa929eb4dc13adb4ee561c9da16835df86727`: M4.5 acceptance process gate, M1/M2/M3 shared Android state
  owner, cross-process OS file lease, WSS callback/retry serialization, and
  strict closed/poisoned identity reads.
- #176 `5ccc713771363bf5ae18ddf87f820903484fffd1`: isolated KDL1 guarded authenticated M5 call-control
  composer, verified full semantic/replay pairing, volatile reducer/timeout
  fencing and one-use effect *proposal* tickets (including simultaneous glare).

Their source file path diffs against protected main are disjoint (25 + 20).
This commit intentionally has BOTH exact Draft commits as parents; its tree
contains the precise source blobs from each branch. CI must independently
compile/run Android JVM, Go/protocol, full repository make test, CodeQL and
supply-chain checks on THIS exact combined head before declaring compatibility.

## Missing security and runtime integration gates

- No production Android factory constructs `IsolatedVoiceForegroundOwner`.
  A shared repository directory or process gate alone is NOT an atomic
  M2/consent, M3 ratchet, encrypted semantic/replay, KDL1 and WSS transaction.
- The proof-of-composition still does NOT execute an E2EE outbound stage,
  socket send, media callback from JNI, PeerConnection, microphone, or ring.
- No stable effect executor is bound to the durable owner. Volatile tickets
  are **not** executable authorization and cannot be passed to live WSS/media.
- Separate Drafts #118 (KAE2), #170 (KCE2), #177 (typed inbound/recovered
  ACK expiry) and the M2/M3 durable cross-store crash recovery remain to be
  incorporated, reviewed and adversarially tested.
- Independent native WebRTC licensing/CVE/ARM64 JNI/video security #88,
  physical P01–P24 #87, Android permission/audio route/two-phone tests,
  and operator-only OCI rollout #91 remain OPEN.

No protected main modifications, no merger of source Drafts, no OCI
host access, APK publication, production voice activation, or M6.
