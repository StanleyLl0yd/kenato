# M5 Android media boundary pre-approval guard

Status: **pre-approval tripwire, not vendor approval**. Tracking issue: #88.
Current production release remains `v0.0.4`; M6 and WebRTC runtime remain out of scope.

`scripts/verify_m5_media_boundary.py` checks reviewed Android source inputs
before ordinary CI and before the release workflow restores signing credentials.
Until the owner accepts a specific patched, verified native WebRTC dependency and
the controlled physical acceptance plan, the source guard rejects:

- known WebRTC/LiveKit/Jitsi/Jingle coordinates in production Gradle build inputs;
- `org.webrtc` and relocated `livekit.org.webrtc` imports or JNI loading
  references in all non-test Android Kotlin/Java source sets;
- vendored AAR/JAR/SO binaries anywhere below `android/app/src`;
- `RECORD_AUDIO`, `FOREGROUND_SERVICE_MICROPHONE`, or a microphone-typed
  foreground service in main and build-variant manifest overlays.

It also fails if its expected Makefile, CI or pre-signing invocation is removed.
Offline synthetic tests exercise unsafe mutations. This defense protects against
accidental promotion of the *known unapproved candidate paths*; it is not a
complete parser of Gradle/Kotlin, does not inspect dynamic classloading, generated
files, transitive/merged manifests or resolved dependencies, and **cannot prove
any AAR safe or free from vulnerabilities**. Maintain the separate isolated AAR,
AGP/D8, Gradle-closure and native-ELF research checks.

WebRTC m150 source at `73cb8180f7258ee292878d6edd05177f41883962`
still matches pre-fix CVE-2026-78891 `rtp_format.cc/.h` blobs. Its binary
exploitability/reachability is **not proven** and its patch status is **not
approved**. The m149 candidate lacks independently established source/GN/patch
lineage. A green media boundary means those candidates were **not introduced**
through the inspected production source paths, not that they were approved.

Removal or relaxation of this guard requires its own security-reviewed PR,
updated patch provenance, binary-native and license review, exact CI and
physical Android 10/13/14+ evidence. No permissions, voice APK, server-side
media infrastructure or release activation is authorized by this guard.
