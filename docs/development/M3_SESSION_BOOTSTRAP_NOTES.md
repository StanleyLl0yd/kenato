# M3 session-bootstrap implementation notes

This file tracks implementation-only constraints for issue #33 while the slice is under review. Durable protocol decisions belong in ADR 0010 and `protocol/README.md`.

- M3 session-account public material is authenticated by the already-pinned Kenato P-256 identity; it is not an independent trust root.
- The invite redeemer initiates the first Olm session; the invite creator responds.
- Fallback keys are intentionally not part of Kenato M3. Exhausted creator one-time keys fail closed.
- A reservation must be atomic and replay-idempotent for the same invite/redeemer while never returning the key to any other invite.
- An initial Olm frame is temporary bootstrap state only. Ordinary encrypted-message transport is M4 and must not appear in this issue.
- Successful creator claim must atomically delete the invite and temporary M3 bootstrap state.
- Server code must validate sizes, counts, protocol versions, ids and generation/revision relationships before expensive signature or database work where practical.
- No log statement may contain invite tokens, signatures, Olm ciphertext, private material, or complete public bundles.
