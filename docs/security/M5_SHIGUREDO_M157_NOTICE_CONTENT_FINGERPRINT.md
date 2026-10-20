# M5: SHA-pinned Shiguredo m157 embedded NOTICE content fingerprint

Status: independent research, **NO LICENSE OR BINARY APPROVAL**.
The exact GitHub-released AAR remains pinned by 15036224 bytes and
SHA256 b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a.

Earlier #148 established that the actual archive contains META-INF/NOTICE.
This stage records bounded SHA-256 and size of its real bytes plus presence of
two descriptive text markers. The result distinguishes a merely named ZIP
member from a populated notice without emitting any third-party content.

The ZIP structure, full CRC and AAR hash are verified by the existing
offline auditor *before* this content inspection. Notices >2 MiB or empty
are rejected. Tests reject missing, oversized or too many entries.

No inference of SPDX completeness, exact license obligations, producer
build reproducibility or CVE remediation is permitted. The vendor remains
unapproved. No Android dependency, JNI execution, permissions, server,
release signing, M6 or production code changes.
