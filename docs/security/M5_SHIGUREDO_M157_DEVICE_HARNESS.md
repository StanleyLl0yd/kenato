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
