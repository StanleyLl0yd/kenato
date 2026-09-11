# M3 session-bootstrap implementation notes

The #33 protocol/server bootstrap slice is implemented. This file keeps the implementation constraints that also govern the Android #34 boundary; durable protocol decisions live in ADR 0010 and `protocol/README.md`.

- M3 session-account public material is authenticated by the already-pinned Kenato P-256 identity; it is not an independent trust root.
- The invite redeemer initiates the first Olm session; the invite creator responds.
- Fallback keys are intentionally not part of Kenato M3. Exhausted creator one-time keys fail closed.
- The normal client OTK target is 32 and the protocol/runtime/persisted-state hard maximum is 50.
- A reservation is atomic and replay-idempotent for the same invite/redeemer while never returning the key to any other invite.
- Creator account rollover retires reservations from the replaced creator generation. Redeemer account rollover preserves the creator OTK reservation but invalidates an already-submitted init from the replaced redeemer generation so a replacement init can use the same reservation.
- The outbound client persists the exact initial pre-key frame before submitting it. Failed submission/restart retries the same frame; successful submission is followed by a cancellation-insensitive durable pending-frame clear.
- Successful creator claim is destructive on the server. After that boundary the responder verifies all returned M2/M3 provenance before local commit and does not honor cancellation until verification/commit completes or fails.
- The responder commits the authenticated M2 contact pin before the atomic M3 inbound state. If the first write fails, M3 state/OTK are untouched. If the M3 write fails, the valid M2 pin may remain but no session is persisted and the OTK stays unconsumed; recovery requires a fresh invite.
- The responder requires the returned creator account generation and exact OTK id/public bytes to match local state, verifies the redeemer bootstrap and submit proof, and verifies the decrypted canonical init-control payload before accepting the session.
- An initial Olm frame is temporary bootstrap state only. Ordinary encrypted-message transport is M4 and must not appear in M3.
- Successful creator claim atomically deletes the invite and temporary M3 server bootstrap state.
- Server and Android code validate sizes, counts, protocol versions, ids, and generation/revision relationships before expensive or state-changing work where practical.
- No log statement may contain invite tokens, signatures, Olm ciphertext, private material, pickle keys, plaintext, or complete public bundles.
- Android account/session snapshots are app-private, backup-excluded, encrypted with fresh per-snapshot pickle keys, and protected by Android Keystore-wrapped snapshot keys.
