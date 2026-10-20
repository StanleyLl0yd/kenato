# M5: JDK 25 build-runtime compatibility probe

Status: RESEARCH ONLY, NOT PRODUCTION MIGRATION. 2026-10-20.
Related: #88, #116 and #87.

## Explicit scope

* Keep Java source/target compatibility 17, Kotlin bytecode target 17,
  Android minSdk 26, compileSdk/targetSdk 37.
* Test Temurin JDK25 as a Gradle runtime on existing Gradle 9.7.1,
  AGP 9.4.0 and Compose Compiler 2.4.10 without changing application code.
* Under AGP9 built-in Kotlin, default Kotlin JVM target follows Android
  compileOptions.targetCompatibility; the current app sets it to 17.
* Build existing M3 native JNI for all CURRENT production ABIs. Targeting
  only ARM64 is a separate reviewed M5 change, not part of this probe.
* Neither enable Shiguredo/microphone nor change signed 0.0.4, release
  pipeline, main CI, CodeQL toolchain, server, M6 or infrastructure.

## What is exercised

The isolated workflow m5-jdk25-compatibility.yml uses JDK25 to build the
normal app in debug and release, run lint and unit tests, and produce an
unsigned Android release bundle for CI only. It also scans locally generated
Kenato classfile inputs (loose classes and jars in Gradle intermediates/tmp),
rejects JVM classfile major >61, and requires MainActivity.class to exist.
No APK/AAB is uploaded, published or signed by this workflow.

The workflow does NOT test a real WebRTC JNI loader, solve native CVEs, prove
source-to-AAR provenance, or exercise a physical Android phone.

## Promotion gates

1. Exact-head JDK25 research build PASS, plus existing CI, CodeQL, Gitleaks,
   Security/Quality and Dependency Review PASS.
2. Inspect warnings and compare the JDK25 build against the existing JDK17
   baseline using similar CI runners/cache conditions.
3. In a separate reviewed PR, optionally switch main Android CI and CodeQL
   build runtime to JDK25, keeping the Java17 bytecode target. Run full
   repository make test. Release-signing workflow changes require a
   separate explicit review and acceptance.
4. Keep #88/#116/#87 open pending source security proof and physical tests.

## CI adoption candidate (separate PR)

Following the successful isolated run on PR #145 (1881 classfile entries,
all major <=61), the next change tests JDK25 in standard Android CI,
repository-wide make test and Java/Kotlin CodeQL only. The release signing
workflow remains JDK17 until separately reviewed. Native and AAR vendor
acceptance, physical JNI and #87 tests remain independent.
