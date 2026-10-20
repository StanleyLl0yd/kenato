# Shiguredo m157 ARM64 ELF hardening inventory — research only

SHA-pinned AAR: b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a
Tag: m157.8103.0.0. No production WebRTC changes or runtime execution.

The existing AAR integrity/ZIP/ELF auditor validates the complete exact
snapshot. The new research job reads only its bounded ARM64 shared library
and feeds a disposable filesystem copy to host readelf (ELF inspection,
not dynamic execution). It records DT_NEEDED, SONAME, RELRO, BIND_NOW,
executable GNU_STACK status, JNI_OnLoad and JNI export counts, along with
the native library SHA-256 and size. Embedded native string markers are
explicitly NOT a CVE reachability or remediation proof.

Even full ELF hardening is not a source-to-binary attestation or proof of
the three named CVE fixes. Android phone JNI loading and #87 P01-P24 remain
mandatory, as do full SPDX notices and upstream patch application evidence.

## ELF 16KiB page alignment guard

The exact m157 ARM64 ELF has three PT_LOAD segments with p_align=0x4000
(16384 bytes), observed by host readelf. The pinned-source research probe
now verifies all PT_LOAD alignments, power-of-two and file/virtual congruency
directly in bounded ELF64 bytes, with synthetic 4KiB/misaligned negative tests.
This is NOT a final APK ZIP alignment check, device JNI load or CVE proof.
