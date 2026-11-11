# M5 audit finding: M1 destructive identity recovery ordering

Status: **DRAFT CORRECTION / NOT PHYSICALLY APPROVED**.
Owner issue #87 (P22 identity state / Keystore restoration).

## Found on protected main

`LocalIdentityRepository.resetLocalIdentityForRecovery()` formerly cleared
the M1 SharedPreferences identity blob before attempting deletion of its
Android Keystore identity/signing and wrapping keys. If key deletion then
failed, app-private state was gone while old keys might still be live.
Restoring an older genuine persisted state could potentially regain an old
cryptographic identity if all original aliases survived. The reset method
already required explicit invocation; this is about ordering/failure
semantics, not remote access or proof that identity was compromised.

## Proposed correction

Delete and independently verify all managed Keystore keys **first**, then
clear the state. If deletion fails or any managed alias is still present,
refuse to clear state or silently regenerate identities. If state deletion
subsequently fails, the old file remains but the keys have been invalidated,
so loading must fail closed. Recovery after a partial deletion requires
separate user-approved explicit recovery, not an automatic retry that masks
the failure.

New JVM fault injection exercises failed pre-deletion, partial mutation,
silent partial deletion and failure of the second (file) step. This is
not a physical Android Keystore, process-death or power-loss test.
Unlike encryption of a consent or M3 file, a key-first order affects
foundational M1 identity and must not be merged until independently
reviewed for recovery UX, multi-process constraints and upgrades.
Production v0.0.4, voice runtime, server and M6 remain unchanged.
