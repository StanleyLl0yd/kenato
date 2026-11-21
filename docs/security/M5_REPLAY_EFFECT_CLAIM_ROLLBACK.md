# M5 replay-effect claim continuity: pre-activation security finding

Status: **CONFIRMED CODE-PATH WEAKNESS / TWO ADVERSARIAL JVM REGRESSIONS**.
Not an active exploit against voice calling: production effects/voice runtime
are still disabled. Tracker #87 (P13/P14), #116 (durable owner), and #170
(separate consent rollback). M5 OPEN, M6 not authorized.

## Evidence on exact main

The replay journal persists `dispatchClaimed` in
`kenato_voice_replay_v1.state` using `AtomicFileVoiceSignalReplayStore`.
The encoded `VoiceSignalReplayStateCodec` format uses a plain SHA-256
checksum, not a keyed authentication or hardware-backed monotonic counter.
`claimLiveDispatchPermit` checks the recorded flag, writes an updated
AtomicFile, then returns true. Consequently:

1. Restore an older *authentic* unclaimed copy after a successful claim:
   `claimLiveDispatchPermit` returns true a second time.
2. A disk-writing adversary can decode, set `dispatchClaimed=false`, recompute
   the unkeyed checksum via the canonical codec and regain claimability.

The new tests deliberately **PASS when this flaw is reproduced**. A green CI
result is not at-most-once side-effect acceptance and does not discharge P13
or P14. Actual production code does not execute native voice effects yet.

The separate encrypted semantic-event file uses a persistent AES-GCM
`com.sl.kenato.m5.voice-semantic.v1` key. It authenticates bytes, but a
previous genuine encrypted file remains readable under that key. Restoring
multiple separate old files can therefore defeat their current cross-store
freshness expectations. Neither the M3 KAE2 proposal (#118) nor consent KCE2
(#170) automatically secures this journal.

## Required security design before activation

- The actual M2/M3/WSS lifecycle/effect owner (#116) must serialize
  authenticated incoming import, canonical semantic ciphertext, dispatch claim
  persistence, revalidation of pinned consent, and real effect execution.
- A **single trusted monotonic continuity boundary** must cover at-most-once
  replay claims across process restart/file restoration. Per-file independent
  AES-GCM authenticity and a checksum are insufficient.
- Define failure/reboot/old-file restore behavior for atomic commits,
  Keystore epoch retirement and independently persisted semantic state.
  Failed and uncertain writes must never authorize a side effect.
- Keep old APK/upgrade/downgrade and identity destructive-recovery states
  explicit; never reset a journal or silently regenerate keys to succeed.
- Execute physical P13/P14 replay, crash, renewal and rollback acceptance
  on Android 10/13/14+ after owner integration, then full security review.
  No microphone, TURN, deployment, production migration or APK release now.

**This is a blocker to future voice-effect execution, not a claim that
currently disabled WebRTC has already run an effect twice.**
