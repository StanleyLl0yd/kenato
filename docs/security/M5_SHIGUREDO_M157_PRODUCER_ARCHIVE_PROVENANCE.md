# M5 Shiguredo m157 producer CI archive identity — proven

Research only; no production WebRTC/vendor approval.

- Exact Shiguredo producer CI: https://github.com/shiguredo-webrtc-build/webrtc-build/actions/runs/38522776327
- Run head `c575fdf836d1185d8cefda37197a2a489e95ffd9`, tag `m157.8103.0.0`.
- Original workflow artifact ID **11876415141**, GitHub Actions ZIP
  **105467424 bytes**, SHA-256
  `8b6dd31f83b78b40d1239d588f50d93fe84008b021a720c89ddc3e11081d8e53`.
- The ZIP has one `webrtc.android_sdk.tar.gz` member, stream-inspected without
  filesystem extraction. It contains 59493 tar entries, among them
  `webrtc/aar/libwebrtc.aar` of **15036224 bytes**, SHA-256
  `b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a`.
- This **exactly equals** the separately pinned published m157 release AAR.
- The same producer tar contains `webrtc/VERSIONS`, with both
  `WEBRTC_COMMIT` and `WEBRTC_SRC_COMMIT` equal to
  `b321f634929af0af61a8964487fbd7894a008f12`.

Use `scripts/verify_shiguredo_m157_producer_archive.py` to repeat this offline
on the original GitHub Actions ZIP. It strictly pins outer hash/size, reads
tar data streams without extraction, validates one nested AAR and source
metadata. Its synthetic negative tests run in `make test-security`.

**Not proven:** an independent reproducible build from source, exact applied
GN/patch/NDK flags, machine-code CVE fixes, complete SPDX obligations, JNI
on physical Android or any voice call. #88/#87/#116 remain OPEN.

## Exact NOTICE byte identity

The SHA-pinned producer CI archive also contains `webrtc/NOTICE` of 214353
bytes, SHA-256 `e5e1a734e1f1e73a0526a4f6ab857f26c4657eb5a70c4f4bc05c20c5444e1ec9`.
The exact nested release-equivalent AAR contains `META-INF/NOTICE`, same length,
same SHA-256 and **identical bytes**. The offline verifier now checks both
members and pins their hashes before reporting success.

This is **not** a full transitive SPDX or redistribution review; neither the
count nor the presence of WebRTC notices proves license completeness.
