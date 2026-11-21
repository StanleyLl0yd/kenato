# M5: isolated Shiguredo ARM64 physical JNI smoke harness

**Not executed, not vendor-approved, not a release.**
Build JDK25 / AGP9.4 / SDK37 with app bytecode17 and only ARM64 native ABI.
Separate application identity `org.kenato.m5jnisentinel`; no Android
permissions, backup, microphone, network, logging of SDP/ICE/keys, or
changes to Kenato production Android or published v0.0.4.

Builds happen automatically for a PR, with JSON-only evidence. A manual
workflow_dispatch requires explicit unapproved-native-risk acknowledgement;
only then can a short-lived (3-day) research APK be uploaded for a controlled
physical-device acceptance campaign. Debug-signed ephemeral, NOT release.

After independent native CVE, provenance and license review authorizes
physical execution, on spare ARM64 Android 10/13/14+ phones: install
the exact SHA-pinned research APK; tap Run local JNI smoke; capture only
fixed PASS_JNI_FACTORY_DISPOSE or E_* diagnostic, Android/API/security patch,
APK SHA256, UTC timestamp. Do not collect serials, raw bugreports or logs.

No device is tested by CI; factory initialization/disposal does not establish
two-phone calls, microphone permission compliance, or #87 P01-P24.
#88/#116/#87 remain OPEN; M6 prohibited.

## 16KiB APK ZIP alignment gate

The disposable device APK build now runs official Android SDK37
`zipalign -c -P 16 -v 4` after checking the merged manifest and native
package inventory. Missing zipalign, misaligned uncompressed `.so`, or an
inconclusive tool result fail closed. This is a read-only check; it does not
rewrite or re-sign the APK. It complements the pinned AAR ELF PT_LOAD 16KiB
check in #155; full Android device/API execution and release AAB alignment
are still NOT proven. Reference: https://developer.android.com/tools/zipalign

## Two independently pinned m157 candidate APKs

The source-controlled research probe accepts only the original
`m157.8103.0.0` and newer `m157.8103.4.0` tags. Each must match its own
publisher AAR SHA-256 and byte count **before any Gradle build**. PR builds
prepare separate permissionless ARM64 debug APKs only in disposable directories;
only version-labeled JSON evidence is uploaded. No vendor binary or APK is
retained as a PR artifact, and no JNI function is invoked by CI.

The manual `workflow_dispatch` still requires `reviewed_native_risk=true`
**before** building or uploading a selected candidate APK. Its explicit
`candidate_tag` choice is restricted to those two SHA-pinned versions. The
3-day APK artifact must not be installed until separately approved native CVE,
license and binary-provenance review. Source revision in the JSON remains an
unverified publisher declaration, not reproducible compiled provenance.
