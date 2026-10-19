# M5 real AAR AGP/D8 research checkpoint

Status: RESEARCH ONLY. No WebRTC vendor approval, release change or microphone activation.

This isolated probe compiles the two exact observed Maven candidate bytes
(m149 and m150) with the same Android plugin 9.4.0, JDK 17, API 37 and Gradle
wrapper 9.7.1 as Kenato. It checks that the disposable debug APK contains the
PeerConnection class in a real DEX class definition and packages exactly the
three required native ABIs. An extra x86 library in the original vendor AAR
must be removed by the app packaging filters.

The probe uses independent temporary application projects. It neither
changes android/app/build.gradle.kts nor runs the Android JNI loader.
The temporary APK and AAR snapshots are never uploaded as artifacts; only
sanitized JSON is retained for seven days. It fails closed on a digest drift,
invalid AAR, Gradle/D8 failure, missing DEX class, or unexpected ABI.

The hardcoded SHA-256 values are historical CI observations, not independently
validated publisher signatures or build reproducibility. Direct file-based
AAR dependency testing also does NOT establish a Maven/POM/Gradle transitive
dependency closure.

Before #88 approval: independently verify publisher/source/GN flags,
license notices and CVE applicability including native code, official Maven
POM/transitive dependencies, and real Android 10/13/14+ JNI load/device
behavior. P01-P24 under #87 and #116 must be physically accepted separately.
No M6, STUN/TURN, OCI rollout, third-party server or production WebRTC runtime.
