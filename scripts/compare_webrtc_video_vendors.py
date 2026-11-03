#!/usr/bin/env python3
"""SHA-pinned AAR video comparison for Kenato; never executes vendor native code."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

import collect_webrtc_candidate_evidence as evidence
import probe_shiguredo_m157 as shiguredo
import probe_shiguredo_m157_d8 as d8
import probe_webrtc_agp as agp
import probe_webrtc_native_elf as native

VENDORS = {
    "shiguredo_m157_8103_4_0": (
        shiguredo.PATCH_RELEASE_URL,
        shiguredo.PATCH_EXPECTED_SHA256,
        shiguredo.PATCH_EXPECTED_SIZE,
    ),
    "webrtc_sdk_v150_7871_04_full": (
        "https://github.com/webrtc-sdk/android/releases/download/v150.7871.04/libwebrtc.aar",
        "f15e6bf94c1cbb9d6defaa95f04d1ae16b84e897f584032781091022d8366e30",
        49068339,
    ),
}
REQUIRED_VIDEO_API = (
    "Camera2Enumerator", "VideoCapturer", "VideoSource", "VideoTrack",
    "VideoFrame", "VideoSink", "SurfaceViewRenderer",
    "DefaultVideoEncoderFactory", "DefaultVideoDecoderFactory",
    "HardwareVideoEncoderFactory", "HardwareVideoDecoderFactory",
    "VideoEncoderFactory", "VideoDecoderFactory", "VideoCodecInfo",
)
OPTIONAL_VIDEO_API = ("Camera1Enumerator", "SoftwareVideoEncoderFactory",
                      "SoftwareVideoDecoderFactory", "EglBase")
LIB = "jni/arm64-v8a/libjingle_peerconnection_so.so"
VIDEO_CLASSES = "org/webrtc/"
MAX_AAR_BYTES = 64 * 1024 * 1024

class CompareError(ValueError):
    pass

def verify_pinned(label: str, digest: str, size: int) -> None:
    if label not in VENDORS:
        raise CompareError("Unreviewed vendor")
    _url, expected, expected_size = VENDORS[label]
    if digest != expected or size != expected_size:
        raise CompareError("AAR digest or byte count differs from pinned publisher release")

def video_class_inventory(api_jar: bytes) -> dict:
    if len(api_jar) > evidence.audit.MAX_JAR_ENTRY_BYTES:
        raise CompareError("Oversized API JAR")
    try:
        with zipfile.ZipFile(io.BytesIO(api_jar)) as jar:
            names = [entry.filename for entry in jar.infolist() if not entry.is_dir()]
            if len(names) > evidence.audit.MAX_JAR_ENTRIES or len(set(names)) != len(names):
                raise CompareError("Invalid or duplicate API entries")
            classes = set(names)
    except (zipfile.BadZipFile, RuntimeError) as error:
        raise CompareError("Corrupt API JAR") from error
    required = {name: VIDEO_CLASSES + name + ".class" in classes
                for name in REQUIRED_VIDEO_API}
    optional = {name: VIDEO_CLASSES + name + ".class" in classes
                for name in OPTIONAL_VIDEO_API}
    return {
        "required_video_class_present": required,
        "required_video_api_all_present": all(required.values()),
        "optional_video_class_present": optional,
        "org_webrtc_class_count": sum(
            item.startswith(VIDEO_CLASSES) and item.endswith(".class") for item in classes
        ),
        "java_api_presence_is_not_video_codec_availability": True,
    }

def native_pt_load_alignment(data: bytes) -> list[int]:
    native.elf_header(data, "arm64-v8a")
    if len(data) < 64:
        raise CompareError("Truncated ELF")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize = struct.unpack_from("<H", data, 54)[0]
    count = struct.unpack_from("<H", data, 56)[0]
    if phoff < 64 or entsize != 56 or not 1 <= count <= 64 or phoff + count * entsize > len(data):
        raise CompareError("Bad native PT_LOAD table")
    aligned = []
    for index in range(count):
        p = phoff + index * entsize
        if struct.unpack_from("<I", data, p)[0] == 1:
            offset = struct.unpack_from("<Q", data, p + 8)[0]
            vaddr = struct.unpack_from("<Q", data, p + 16)[0]
            alignment = struct.unpack_from("<Q", data, p + 48)[0]
            if not alignment or alignment & (alignment - 1) or offset % alignment != vaddr % alignment:
                raise CompareError("Invalid native PT_LOAD alignment")
            aligned.append(alignment)
    if not aligned:
        raise CompareError("Missing PT_LOAD segments")
    return aligned

def analyze(label: str, aar: Path, *, scanner=native.scan_elf) -> dict:
    verify_pinned(label, hashlib.sha256(aar.read_bytes()).hexdigest(), aar.stat().st_size)
    structure = evidence.audit.audit_aar(
        aar, expected_sha256=VENDORS[label][1],
        required_abis=frozenset(("arm64-v8a",)), max_classfile_major=69,
    )
    with zipfile.ZipFile(aar) as archive:
        api_info = archive.getinfo("classes.jar")
        so_info = archive.getinfo(LIB)
        if api_info.file_size > evidence.audit.MAX_JAR_ENTRY_BYTES or (
            not 1 <= so_info.file_size <= native.LIMIT
        ):
            raise CompareError("Oversized or empty ARM64 payload")
        api = archive.read(api_info)
        so = archive.read(so_info)
        abi_sizes = {
            entry.filename.split("/")[1]: entry.file_size
            for entry in archive.infolist()
            if entry.filename.startswith("jni/") and
               entry.filename.endswith("/libjingle_peerconnection_so.so")
        }
    java = video_class_inventory(api)
    native_info = scanner(so, "arm64-v8a")
    loads = native_pt_load_alignment(so)
    return {
        "label": label, "aar_sha256": structure["sha256"],
        "aar_download_bytes_all_ABIs": structure["file_bytes"],
        "other_packaged_abis": structure["optional_abis_present"],
        "native_library_bytes_by_abi": abi_sizes,
        "arm64_native_sha256": native_info["sha256"],
        "arm64_pt_load_alignment_bytes": loads,
        "arm64_pt_load_all_16k": all(x >= 16384 for x in loads),
        "arm64_jni_onload_exported": native_info["jni_onload_exported"],
        "arm64_gnu_relro": native_info["gnu_relro"],
        "arm64_bind_now": native_info["bind_now"],
        "arm64_gnu_stack_executable": native_info["gnu_stack_executable"],
        "arm64_diagnostic_video_symbol_markers_NOT_codec_support":
            native_info["binary_marker_counts_NOT_reachability"],
        "jar_classfile_major_counts": structure["java_classfile_major_counts"],
        "aar_notice_filenames": structure["embedded_license_or_notice_paths"],
        **java,
        "actual_video_encoder_decoder_tested": False,
        "camera_capture_executed": False,
        "native_library_executed": False,
        "native_cve_approved": False,
        "license_clearance": False,
        "vendor_approved": False,
    }

def build_disposable_video_api(wrapper: Path, aar: Path, root: Path,
                               *, runner=subprocess.run) -> dict:
    agp.write_disposable_app(root, aar)
    gradle = root / "app/build.gradle"
    value = gradle.read_text(encoding="utf-8")
    if value.count(d8.DEFAULT_ABIS) != 1:
        raise CompareError("Disposable ABI template changed")
    gradle.write_text(value.replace(d8.DEFAULT_ABIS, d8.RESEARCH_ABIS), encoding="utf-8")
    java = root / "app/src/main/java/org/kenato/research/Probe.java"
    java.write_text(
        "package org.kenato.research;\n"
        "public final class Probe {\n"
        "  public Class<?>[] videoApi() { return new Class<?>[]{\n"
        "    org.webrtc.PeerConnection.class, org.webrtc.Camera2Enumerator.class,\n"
        "    org.webrtc.DefaultVideoEncoderFactory.class,\n"
        "    org.webrtc.DefaultVideoDecoderFactory.class,\n"
        "    org.webrtc.VideoTrack.class, org.webrtc.SurfaceViewRenderer.class\n"
        "  }; }\n"
        "  public org.webrtc.VideoEncoderFactory encoder(org.webrtc.EglBase.Context egl) {\n"
        "    return new org.webrtc.DefaultVideoEncoderFactory(egl, true, true);\n"
        "  }\n"
        "  public org.webrtc.VideoDecoderFactory decoder(org.webrtc.EglBase.Context egl) {\n"
        "    return new org.webrtc.DefaultVideoDecoderFactory(egl);\n"
        "  }\n"
        "  public org.webrtc.CameraVideoCapturer capturer(android.content.Context context, String name) {\n"
        "    return new org.webrtc.Camera2Enumerator(context).createCapturer(name, null);\n"
        "  }\n"
        "  public org.webrtc.PeerConnectionFactory.Builder videoFactory(org.webrtc.EglBase.Context egl) {\n"
        "    return org.webrtc.PeerConnectionFactory.builder()\n"
        "      .setVideoEncoderFactory(encoder(egl)).setVideoDecoderFactory(decoder(egl));\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    try:
        result = runner(
            [str(wrapper.resolve()), "--no-daemon", ":app:assembleDebug"],
            cwd=root, check=False, timeout=540, capture_output=True, text=True,
        )
    except subprocess.TimeoutExpired as error:
        raise CompareError("Disposable Android video API compilation timed out") from error
    if result.returncode:
        print("Disposable Android video API build exit:", result.returncode)
        print("\n".join((result.stdout or "").splitlines()[-30:])[:4000])
        raise CompareError("Disposable Android video API compilation failed")
    apk = root / "app/build/outputs/apk/debug/app-debug.apk"
    record = d8.inspect_arm64_apk(apk)
    record["compiled_video_api_references"] = True
    record["video_factory_camera_and_peer_connection_methods_compiled"] = True
    record["camera_opened"] = False
    record["codec_executed"] = False
    return record

def collect(gradlew: Path | None, *, downloader=evidence.download_snapshot,
            scanner=native.scan_elf, builder=build_disposable_video_api) -> dict:
    report = {
        "status": "STATIC_RESEARCH_ONLY_NOT_VENDOR_APPROVAL",
        "baseline": "ARM64 Android API26+ / host JDK25 / Android AGP9.4 when build enabled",
        "candidates": {},
        "video_codec_working_on_real_device_verified": False,
        "camera_permission_or_media_runtime_enabled": False,
        "comparative_video_quality_measured": False,
        "vendor_approved": False,
    }
    with tempfile.TemporaryDirectory(prefix="kenato-video-vendor-compare-") as temp:
        for label, (url, _sha, _size) in VENDORS.items():
            path = Path(temp) / (label + ".aar")
            digest, size = downloader(url, path, max_bytes=MAX_AAR_BYTES)
            verify_pinned(label, digest, size)
            info = analyze(label, path, scanner=scanner)
            if gradlew is not None:
                info["disposable_arm64_video_api_compile"] = builder(
                    gradlew, path, Path(temp) / (label + "-app")
                )
            report["candidates"][label] = info
    return report

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gradlew", type=Path)
    args = parser.parse_args()
    try:
        report = collect(args.gradlew)
        code = 0
    except (CompareError, OSError, ValueError, zipfile.BadZipFile,
            evidence.EvidenceError, evidence.audit.AarAuditError,
            native.NativeProbeError, subprocess.SubprocessError) as error:
        report = {
            "status": "PINNED_VIDEO_VENDOR_COMPARISON_FAILED",
            "error_type": type(error).__name__,
            "error": str(error)[:180],
            "vendor_approved": False,
        }
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print("Two-vendor ARM64 video research:", report["status"])
    for name, details in report.get("candidates", {}).items():
        print(name, "video API classes", details["required_video_api_all_present"],
              "16KiB ELF", details["arm64_pt_load_all_16k"],
              "ARM64 ELF bytes", details["native_library_bytes_by_abi"].get("arm64-v8a"))
    if code:
        print("Probe failure:", report["error_type"], report["error"])
    return code

if __name__ == "__main__":
    raise SystemExit(main())
