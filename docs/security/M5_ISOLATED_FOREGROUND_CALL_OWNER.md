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

A closed owner cancels tickets and timeout fences. A rejected local operation
invalidates outstanding proposals. Any exception during protected inbound claim
terminates the isolated owner, cancels its timers and blocks all subsequent
proposals—even if consent is later restored. A normal absent/duplicate inbound
candidate returns null without closing the owner. This conservative synthetic
fault policy is not a substitute for coordinated durable recovery. No socket send, encrypted M3 staging,
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

## Simultaneous outbound glare: retiring the losing call

The reducer's authenticated glare resolver can produce a combined transition:
retire the losing outgoing call, then display the winning incoming call from
the **same pinned peer**. A strict terminal-only effect gate had mistakenly
rejected the legitimate `SEND_HANGUP` proposal because the new snapshot is
`INCOMING_RINGING`, not `IDLE`. The isolated proposal gate now accepts only
the **most recently retired** old call ID when the active incoming peer is
identical but its call ID differs. Other peers, arbitrary old IDs and any
native/media work remain rejected. Consent is still checked when the one-use
proposal is claimed; no effect is executed by this owner.

The change does not authorize real WSS sending, replace KDL1, or complete the
P01–P24 physical glare tests; it only fixes the isolated reducer/proposal
composition and adds a regression for the genuine simultaneous-call path.
