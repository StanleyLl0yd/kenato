# M5 Android owner, call-control and ACK/recovery source composition

Status: **DRAFT source/CI compatibility only, NO live media or release clearance**.

This integration combines, without merging any parent Draft into protected main:

- #178 at `ec860505959f78ac1f0d9281f4da73e0812fc00a`: exact Android M1/M2/M3/WSS owner and guarded KDL1 proposal composition from #123 and #176.
- #177 at `0f54c9c739aecdbff5171fb0fbdfe978dadd44d5`: verified semantic/replay time-snapshot, recovery, direct and recovered M5 ACK last-moment expiry checks and fail-closed static policy.

Nine #177 paths are imported with their **exact Git blob SHAs**. Two overlapping WSS paths (`MessagingWssCoordinator.kt` and its JVM test) were three-way line merged against exact main `5544c168469b7d91b6d75a222a92ae75890eb415`; their changed line ranges do not intersect. Both branches' changes must be verified together in CI on the resulting exact integration HEAD. A successful build is not a transactional correctness proof.

## Product-first main restack

The original exact-source compatibility evidence above remains scoped to the
historic research parents and the original protected main. The current research
branch is being restacked over the separately reviewed and merged Android product
UI (#180–#182), not merged into production. Its Android
`M45AcceptanceController.kt` is deliberately reconciled with the new
on-success UI callbacks and the original M5 process/trust ownership, so this
**one controller blob is no longer byte-identical** to #123/#178. All other
research source blobs are carried without manual rewrites.

This restack is not a production Android voice owner, security signoff,
native WebRTC approval, physical call result, server deployment or release.
Current exact-head CI/security is mandatory after the restack.

## Acceptance and security limitations

- There is still **no** production Android factory for `IsolatedVoiceForegroundOwner` and no approved execution of the volatile effect proposals.
- Process-local and cross-process WSS leases are not atomic with M2 consent, M3 ratchet persistence, encrypted semantic/replay files, KDL1 claims or native effects. Crash/restart after partial persistence requires independently proven reconciliation; ACK cannot be sent based on partial state.
- #118 Keystore anti-rollback, #170 consent revocation, physical #87 P01–P24, #88 vendor native CVE/licensing/ARM64, #91 operator OCI rollout, #116 complete durable call owner and effect execution remain OPEN.
- No WebRTC dependency, microphone permission, live socket/media effect, server, release, TURN or M6 changes are authorized here.

All exact-head workflow families, Android/JVM synthetic scenarios, repository-wide policy and independent security review must pass before treating this as even a compile/protocol compatibility gate. A failed or skipped required workflow remains a blocker.
