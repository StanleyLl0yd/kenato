# M5 isolated foreground call owner: reducer, KDL1, proposal gate

Status: **DRAFT COMPOSITION; NO PRODUCTION CALL SITES OR LIVE EFFECTS**.
Tracks #87 P13/P14/P17, #116, #168, #174 and #175.

`IsolatedVoiceForegroundOwner` is a process-local proof-of-composition for
three independently tested pieces:

1. A `VoiceCallAdmissionCoordinator` with only the opt-in
   `EpochGuardedVoiceCallClaimedControlSource`. There is **no legacy
   checksum-only fallback** inside this constructor. The inbound source
   revalidates signed pinned contact admission before/after the replay+KDL1
   claim, checks expiry and confirms stable encrypted semantic plaintext.
2. The volatile call reducer and its monotonic timeout fence, with each
   call-control transition registered as the latest local snapshot.
3. The existing research `VoiceEffectClaimGate` (#168), imported without
   relaxing its same-generation/snapshot/call-key and approval policies.
   `Result` exposes the **snapshot and tickets**, not the raw reducer
   effect-list as an executable capability; `claimProposal` checks one-use
   and current approval. `STOP_MEDIA` is still permitted after revoked
   consent, strictly for the already correlated retired call.

A closed owner cancels tickets and timeout fences. A rejected operation
invalidates outstanding proposals. No socket send, encrypted M3 staging,
WebRTC, microphone, audio route, user-visible ring or process restart occurs
in the synthetic tests. This is a **volatile foreground-only composer** and
must never be called a complete durable voice runtime.

## Known unsolved admission and side-effect races

- M2 consent/revocation and M3 ratchet, M4 WSS ACK/recovery and the future
  actual effect executor do **not** share this process monitor.
- A returned ephemeral `VoiceCallEffect` is only a *proposal*. Approval
  may change after ticket claim, before a real network/native side effect.
  Actual execution MUST occur under one reviewed durable owner that owns
  consent epoch, WSS, stable call state, exact media handle and single-use
  durable effect commit.
- KDL1 is capped and fail-closed without automatic recovery/migration.
  Key rotation across a crash is not a cross-store commit.
- Source code and JVM tests cannot prove process-death, reboot, OEM
  Keystore behaviors, multi-process locks or media/native JNI correctness.
- #168 remains a distinct Draft dependency; this stacked PR carries its
  unchanged source into the new research branch. The history must be
  restacked after #168/#174/#175 independently pass review and are accepted.
- All P01–P24 physical scenarios, WebRTC vendor CVEs/licenses, operator
  OCI rollout and release gates remain open. No M6, TURN or new server.

## Synthetic claims and scope

The regression suite covers at-most-once inbound control to the reducer,
one-time outbound ticket, stale-ticket invalidation after a newer transition,
safe local `STOP_MEDIA` *proposal* after consent revocation and owner close.
It does **not** assert exactly-once call execution, or physical media STOP.

Protected main and release v0.0.4 must stay unchanged until separately
approved gates. No APK deployment or production activation.
