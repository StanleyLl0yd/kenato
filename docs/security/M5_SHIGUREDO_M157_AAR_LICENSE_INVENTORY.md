# M5 Shiguredo m157: exact AAR license/NOTICE inventory

Status: RESEARCH ONLY — NOT LICENSE CLEARANCE OR VENDOR APPROVAL.
Parent: #88; pinned asset SHA-256:
b95158860143edd381b804a5f3a8fea371ff24c44c2ebfc9a66c52340d558d3a.

The offline structural auditor already enumerates ZIP entries containing
license or notice in their names, with bounded ZIP processing, hash verification
and CRC. The pinned m157 reporter now exposes these filenames in JSON and
sanitized CI output; no third-party binary is published.

Top-level AAR filename matches do not prove embedded notice content or
third-party completeness. Empty matches do not prohibit redistribution if
applicable licenses are supplied externally, but that requires review.

Publisher source tag m157.8103.0.0 includes Apache-2.0 LICENSE and WebRTC/
WebKit BSD-style NOTICE. Neither establishes full transitive binary inventory.

Independent production acceptance requires mapping all shipped components
to their actual SPDX licenses/attributions. Reporter remains explicitly
vendor_approved_for_kenato=false regardless of these findings.

Only inventory visibility and regression tests change here. No Android app,
runtime, microphone, ABI, server, release, or M6 change.
