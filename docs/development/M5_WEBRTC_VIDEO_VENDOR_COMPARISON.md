# M5: comparative video-readiness of two publisher-prebuilt Android WebRTC AARs

Date: 2026-11-03. Parent #88; research-only Draft PR #172. M5 audio first; one-to-one video is a later **binding vendor-selection requirement**, not M6 authorization.

## Reproducible evidence and exact inputs

Run [GitHub Actions 41622746764](https://github.com/StanleyLl0yd/kenato/actions/runs/41622746764) succeeded: `scripts/compare_webrtc_video_vendors.py` downloads each original full GitHub Release AAR into separate disposable directories, enforces exact independently recorded asset digest and length, runs the repository's bounded AAR/Java/ELF structural audit, inventories video Java classes and ARM64 native hardening, and builds a separate Android app referencing actual video API using JDK25, AGP9.4, SDK37, application bytecode17, minSdk26 and **ARM64 only**. No native JNI or video encoder is executed; no APK/AAR is retained as a GitHub Actions artifact. The only archived artifact is bounded JSON (seven-day retention). A later exact-head workflow additionally compiles Java video encoder/decoder constructors, Camera2 capturer and PeerConnectionFactory methods; verify that new exact-head job separately before claiming its PASS.

- Shiguredo [m157.8103.4.0](https://github.com/shiguredo-webrtc-build/webrtc-build/releases/tag/m157.8103.4.0) full `libwebrtc.aar`: 15,037,143 bytes, sha256 `4ce14722c9c8f633cc9390f0547ee3195ad95cf1eeab18928ced733218d88cd1`.
- [webrtc-sdk/android v150.7871.04](https://github.com/webrtc-sdk/android/releases/tag/v150.7871.04) **unprefixed full**, not prefixed/stripped, `libwebrtc.aar`: 49,068,339 bytes, sha256 `f15e6bf94c1cbb9d6defaa95f04d1ae16b84e897f584032781091022d8366e30`. This is the upstream GitHub Release AAR, **not** the Maven copy modified by the publisher's `downloadAar.sh` Java-classfile-major header rewriting.

## Exact-arm64 static and disposable-build results

| Measurement | Shiguredo m157.8103.4.0 | webrtc-sdk/android v150.7871.04 full |
|---|---:|---:|
| Publisher AAR bytes | 15,037,143 | 49,068,339 |
| Packaged ARM64 JNI ELF bytes | 13,522,664 | 12,266,048 |
| Packaged non-target ABI entries | none | armeabi-v7a, x86, x86_64 |
| Disposable **ARM64-only** APK bytes | 14,688,108 | 13,382,340 |
| Required Android video classes present | 14/14 | 14/14 |
| Extra SoftwareVideoEncoder/DecoderFactory classes | both present | both present |
| HardwareVideoEncoder/DecoderFactory classes | both present | both present |
| Camera1/Camera2 and EGL-related APIs | present | present |
| JDK25 + AGP9.4 disposable video class-ref compile + D8 | PASS | PASS |
| ELF PT_LOAD alignments in bytes | 16,384 × 3 | 16,384 × 3 |
| ELF GNU_RELRO / BIND_NOW / non-executable stack | PASS | PASS |
| JNI_OnLoad exported | yes | yes |
| Original Java classfile major / count | 69 / 521 | 65 / 433 |
| AAR-embedded NOTICE inventory | `META-INF/NOTICE` | none embedded |
| JNI loader / camera capture / codec execution on phone | NOT RUN | NOT RUN |
| Native CVE and third-party-license acceptance | NOT APPROVED | NOT APPROVED |

The ~3.26x all-ABI **AAR** difference does not carry into an ARM64-only APK. For the **disposable test** (not a Kenato production APK), the full webrtc-sdk build is 1,305,768 bytes smaller, and its ARM64 native library is 1,256,616 bytes smaller. These are not RAM/CPU/video-quality/thermal/battery measurements. Presence of the same Java API types does not prove the same codecs, hardware drivers or real video interoperability.

## Meaningful video/security distinctions

1. **Both retain the Java video interface:** Camera2Enumerator, VideoCapturer, VideoSource/Track/Frame/Sink, SurfaceViewRenderer, codec info and default/hardware encoder+decoder factories all appear in the verified JAR, and six representative video Java class references built under the same disposable AGP toolchain. Software encoder/decoder factory classes also appear in both, but **class presence is not evidence a requested codec can actually encode**. The webrtc-sdk publisher explicitly states that its **prefixed-stripped** variant removes software video codecs: do not substitute it for the full variant.
2. **Shiguredo build flag requires a dedicated H.264 gate.** In publisher tag `m157.8103.4.0` `run.py`, `COMMON_GN_ARGS` contains `rtc_use_h264=false`; the publisher's release workflow invokes `python3 run.py build ... --no-history` without overriding GN args. The implication for H.264 **Android hardware versus software** negotiation must be verified on devices; **do not claim Shiguredo H.264 encode/decode support based on camera/factory Java class presence**. VP8 also requires an actual negotiated and encoded end-to-end video test.
3. **webrtc-sdk full AAR is smaller for actual ARM64 packaging** and exposes the same inspected Java video API. Its README documents software-video-codec removal only in the separate stripped variant, which is excluded here. The publisher Android changelog for 150.7871.04 additionally mentions eMudhra certificate remediation; that **does not establish independent WebRTC-native CVE clearance**.
4. **Source, patch and licensing evidence differ.** Shiguredo m157 has an embedded 214 KiB publisher NOTICE already separately matched to producer archive; this is **not** a complete third-party SPDX inventory. The full webrtc-sdk AAR has no embedded NOTICE file; external binary-component/attribution duties need separate resolution. The existing #88 pre-fix VP9 source finding in the older m150 producer lineage is **not closed** by this comparison; investigate the exact v150.7871.04 producer source/patch lineage and binary applicability.
5. **Build compatibility:** Shiguredo's original classfiles are major69 (Java25), and the original full webrtc-sdk release classfiles are major65 (Java21). JDK25 + AGP9.4 compiled both in isolated APKs without changing Kenato's Java17-owned source or production Gradle. The webrtc-sdk Maven publishing helper **rewrites classfile major values to 61**, which is not source recompilation; production consumption requires separate verified Maven-vs-release bytes/D8 semantics.

## Decision and remaining gates

**Both candidates pass static video-API and disposable ARM64 build prerequisites. Neither passes the actual video-call or native-security acceptance gate.** Retain Shiguredo m157 as the earlier owner-selected **research preference**, not a permanently selected production vendor, and keep complete webrtc-sdk m150.04 as a credible alternative. Because of Shiguredo's explicitly disabled `rtc_use_h264` GN flag, dynamic codec negotiation is a material selection criterion, not a cosmetic one. Do not substitute the source branch's later feature claims for what the pinned AAR demonstrably does.

Before finally choosing: inspect software/hardware VP8 and H.264 `getSupportedCodecs()` and true encoder/decoder functionality on two physical ARM64 Android phones; test camera capture → local/remote rendering, rotation, repeated close/reopen, permission refusal and sustained-call resource use; verify native CVE patches/lineage and transitive attribution for the **exact chosen AAR**. Maintain E2EE authenticated SDP/DTLS fingerprint binding, one-time effect gate, #87 P01–P24, #91 rollout and #116 owner gates. No WebRTC injection into production, camera/microphone permission, TURN, M6, release or protected main change is authorized by this research.
