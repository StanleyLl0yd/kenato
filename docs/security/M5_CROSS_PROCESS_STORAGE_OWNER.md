# M4.5 storage ownership and M5 continuity boundary

Trackers: #116, #118, #170, #171, #87. This is an integration prerequisite, not a rollback fix or a media acceptance result.

## Advisory process lease

The existing research lease from #179 is brought into the current M4.5 entrypoint, without importing the rest of that Draft. The canonical no-backup directory identifies one process gate and one persistent lock file. A nonblocking exclusive FileChannel lock is held for the process lifetime; Activity recreation, runtime stop and service-origin changes must not close it. The lock file is never removed by the lease implementation. A failed acquisition does not cache a lease; a previously acquired but lost lease is never replaced in the same process.

The controller acquires the lease on its worker before opening persisted preferences, identities, contacts or conversation snapshots, and before explicit operations. The runtime factory requires it before constructing repositories. Callback activation and trust mutations must check the same lease. Explicit local revocation remains independent of WSS poison, but cannot bypass a foreign process's storage ownership. A lock failure denies the operation and redacts any previously displayed private UI snapshot and QR without resetting identity, deleting state or releasing another operation's busy ticket. Recovery may refresh data after initial contention; a lost acquired lease remains terminal in that process.

The lease is advisory. It protects cooperating entrypoints using the same persistent inode, not arbitrary code with the app UID, a replaced lock inode, a compromised OS, or a rolled-back file. No new Android process, permission, server, media dependency, or storage format is introduced. Host JVM subprocess tests are not Android device evidence; verify the actual filesystem/NOFOLLOW support, independent-process contention, process death, restart and retained M4 data on supported Android devices before claiming physical acceptance.

## Remaining durable owner contract

M3 handoffs, M2 consent, replay receipts/claims and encrypted semantic events currently persist independently. Neither this lease nor KAE2/KCE2/KDL1 research alone establishes their joint freshness. Process death releases the OS lock, not any incomplete transaction. Before executing real voice effects or sending a voice ACK, the production owner must establish and verify:

- A single authenticated generation binding the exact current owner identity, M2 consent, M3 state, semantic receipts and one-use claims; no independent store may issue effect authority.
- A reviewed crash/recovery protocol for each write, verification and Keystore retirement boundary; ambiguous generations, missing keys, conflicting receipts and downgrade must deny effects and voice ACKs rather than recover from an unverified older state.
- Explicit migration and destructive recovery, with no automatic re-grant of historical consent or unclaimed effects and no silent loss/reset of M4 identity or history.
- Device tests with restored, deleted, mixed-generation and interrupted snapshots; verified non-rollback of the relevant Keystore namespace and measured commit latency. The threat model must state the limits of OS/UID/Keystore compromise.

#179 remains research only. #118/#170/#171 remain open. The actual two-phone P01–P24, independent native/security/license approval under #88, whole-repository acceptance, and #116 remain mandatory. No microphone, WebRTC, TURN, OCI deployment, release or M6 is authorized by this prerequisite.

## Isolated Android lease probe (NOT RUN)

The opt-in `m5StorageProbe` build type compiles the real lease and gate into
a separate test-only application ID `com.sl.kenato.m5storageprobe`. It removes
the launcher and INTERNET permission, adds no microphone or vendor dependency,
and uses a nonexported bound service in a separate process. The instrumentation
refuses to operate outside that package and uses three fresh randomly named
private directories, never the real application's storage or keys. CI compiles
and checks package/permissions only; it does not install, execute or publish it.

After exact-source review and explicit operator authorization, on a disposable
test phone with Android SDK/ADB connected, build from the reviewed commit with
the existing pinned native build prerequisite, then:

```sh
./gradlew --no-daemon -PkenatoM5StorageProbe=true :android:app:assembleM5StorageProbe
adb install -t android/app/build/outputs/apk/m5StorageProbe/app-m5StorageProbe.apk
adb shell am instrument -w com.sl.kenato.m5storageprobe/com.sl.kenato.storage.M45StorageLeaseInstrumentation
```

Verify the package and signer and record APK SHA-256 independently before
installation. Select an explicit device with `adb -s SERIAL` if more than one
is attached; never publish the serial. Accept only `INSTRUMENTATION_CODE: -1`
and `storage_lease_probe=PASS`, with all fixed case IDs L01-L05 marked PASS.
Otherwise report FAIL/BLOCKED; do not retry by clearing real Kenato data.
Record exact commit, APK hash, Android API/security patch and model, and
redacted fixed case results. Repeat on Android 10/13/14+; API 26-28 are also
supported by the app and should be explicitly qualified. Uninstall only the
disposable probe package when authorized; never uninstall `com.sl.kenato`.

L01 actual exclusive lock, distinct Android PIDs and foreign contention;
L02 competing process owns a second directory, gate denies writes and revoke;
L03 binder death after killing only the probe service, new owner can acquire
without losing the sentinel; L04 lost local lease denies callback and mutation;
L05 symlink refusal. These cases exercise kernel/provider behavior, not the
real M4 app upgrade, process-restart durability, Keystore or P01-P24.
Actual M4 retained-state verification and independent review remain separate.
