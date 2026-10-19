# M5 published Maven metadata/Gradle closure research

Status: RESEARCH ONLY. Parent #88. No WebRTC vendor approval.

The first #139 D8/AGP investigation compiled exact local AAR bytes. This
follow-up probes the official Maven Central coordinates with the same
disposable AGP 9.4.0/JDK 17/API 37 application shape, capturing the
debugRuntimeClasspath dependency graph, artifact module IDs, SHA-256 of
Gradle-resolved artifacts and the resulting APK's DEX/JNI ABI inventory.

Expected root AAR digests are historical Kenato CI observations. Matching
them to Gradle-selected AARs detects mirror/candidate drift, but does not
authenticate a publisher or reproduce upstream WebRTC source builds.
m149's published POM declares kotlin-stdlib 2.2.10; the probe checks
that Kotlin stdlib is present in the real resolved graph.

The workflow runs only for related PR paths or explicit dispatch.
All AARs, dependencies and throwaway APKs remain outside the checkout.
Only sanitized JSON observations are uploaded for seven days. No Kenato
production dependency, mic permission, JNI loader invocation, server,
STUN/TURN, release or M6 modification.

Unresolved #88 gates: independent publisher signature and binary source/GN
flags, complete bundled native license/notice and CVE applicability review,
actual Android 10/13/14+ loader and two-phone #87/P01-P24 acceptance, and
#116 effect runner approval.
