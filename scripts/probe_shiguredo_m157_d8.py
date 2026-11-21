#!/usr/bin/env python3
"""Disposable AGP 9.4/D8 JDK25 ARM64 integration research for pinned m157.

Never executes JNI, accesses microphone, modifies production Gradle or
publishes the vendor AAR/APK. Passing does NOT approve this vendor.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tempfile
import zipfile
from pathlib import Path

import collect_webrtc_candidate_evidence as evidence
import probe_webrtc_agp as agp
import probe_shiguredo_m157 as m157

RESEARCH_ABI = "arm64-v8a"
DEFAULT_ABIS = "abiFilters 'armeabi-v7a', 'arm64-v8a', 'x86_64'"
RESEARCH_ABIS = "abiFilters 'arm64-v8a'"


class D8ResearchError(ValueError):
    pass


def write_arm64_probe(root: Path, vendor_aar: Path) -> None:
    agp.write_disposable_app(root, vendor_aar)
    gradle = root / "app/build.gradle"
    text = gradle.read_text(encoding="utf-8")
    if text.count(DEFAULT_ABIS) != 1:
        raise D8ResearchError("Unrecognized upstream disposable ABI fixture")
    updated = text.replace(DEFAULT_ABIS, RESEARCH_ABIS)
    anchor = "    targetSdk 37\n"
    if updated.count(anchor) != 1:
        raise D8ResearchError("Unrecognized disposable version metadata fixture")
    updated = updated.replace(
        anchor, anchor + "    versionCode 1\n    versionName '0.0.0-research'\n"
    )
    gradle.write_text(updated, encoding="utf-8")


NOTICE_SHA256 = "e5e1a734e1f1e73a0526a4f6ab857f26c4657eb5a70c4f4bc05c20c5444e1ec9"
NOTICE_BYTES = 214353
NOTICE_ASSET = "app/src/main/assets/legal/NOTICE"
AAB_NOTICE_ENTRY = "base/assets/legal/NOTICE"
AAB_JNI_ENTRY = "base/lib/arm64-v8a/libjingle_peerconnection_so.so"
BUNDLETOOL_SHA256 = "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
BUNDLETOOL_BYTES = 32520401
MAX_APK_SET_BYTES = 160 * 1024 * 1024
MAX_SPLIT_APK_BYTES = 60 * 1024 * 1024
MAX_NATIVE_ELF_BYTES = 24 * 1024 * 1024
DEVICE_SDKS = (29, 34)


def include_reviewed_notice_asset(root: Path, aar: Path) -> None:
    """Place exact publisher NOTICE in a disposable app, never production."""
    try:
        with zipfile.ZipFile(aar) as archive:
            entry = archive.getinfo("META-INF/NOTICE")
            if entry.file_size != NOTICE_BYTES:
                raise D8ResearchError("Unexpected third-party NOTICE size")
            notice = archive.read(entry)
    except (zipfile.BadZipFile, KeyError) as error:
        raise D8ResearchError("Missing or invalid verified publisher NOTICE") from error
    if len(notice) != NOTICE_BYTES or hashlib.sha256(notice).hexdigest() != NOTICE_SHA256:
        raise D8ResearchError("Publisher NOTICE SHA-256 changed")
    target = root / NOTICE_ASSET
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(notice)



def sha256_native_member(archive: zipfile.ZipFile, name: str) -> str:
    """Read a bounded native ZIP member only; never load JNI."""
    try:
        item = archive.getinfo(name)
    except KeyError as error:
        raise D8ResearchError("Expected native JNI ZIP member absent") from error
    if not 64 <= item.file_size <= MAX_NATIVE_ELF_BYTES:
        raise D8ResearchError("Invalid native JNI size")
    with archive.open(item) as stream:
        data = stream.read(MAX_NATIVE_ELF_BYTES + 1)
    if len(data) != item.file_size:
        raise D8ResearchError("Truncated native JNI member")
    return hashlib.sha256(data).hexdigest()


def inspect_arm64_apk(path: Path, *, expected_native_sha256: str | None = None) -> dict:
    if not path.is_file() or path.stat().st_size > agp.MAX_APK:
        raise D8ResearchError("Missing or oversized disposable APK")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [x.filename for x in entries]
        if len(names) > evidence.audit.MAX_ENTRIES or len(names) != len(set(names)):
            raise D8ResearchError("Unexpected APK entry inventory")
        native = sorted(name for name in names if name.startswith("lib/") and name.endswith(".so"))
        if not native or {name.split("/")[1] for name in native} != {RESEARCH_ABI}:
            raise D8ResearchError("Disposable APK contains incorrect native ABI selection")
        expected_jni = "lib/arm64-v8a/libjingle_peerconnection_so.so"
        if expected_jni not in native:
            raise D8ResearchError("ARM64 WebRTC JNI library was not packaged")
        native_sha = sha256_native_member(archive, expected_jni)
        if expected_native_sha256 is not None and native_sha != expected_native_sha256:
            raise D8ResearchError("APK JNI does not match exact pinned AAR ELF")
        dex_paths = sorted(name for name in names if name.startswith("classes") and name.endswith(".dex"))
        if not dex_paths:
            raise D8ResearchError("No compiled DEX files")
        found = False
        for name in dex_paths:
            info = archive.getinfo(name)
            if info.file_size > agp.MAX_DEX:
                raise D8ResearchError("Oversized DEX file")
            with archive.open(info) as stream:
                data = stream.read(agp.MAX_DEX + 1)
            if len(data) != info.file_size:
                raise D8ResearchError("Incomplete DEX file")
            found = agp.dex_defines_class(data) or found
        if not found:
            raise D8ResearchError("PeerConnection is absent from compiled DEX")
        notice_candidates = sorted(
            name for name in names if
            name.lower() == "notice" or name.lower().endswith("/notice")
        )
        notice_entries = []
        for name in notice_candidates[:32]:
            info = archive.getinfo(name)
            if info.file_size > 2 * 1024 * 1024:
                raise D8ResearchError("Oversized notice candidate in disposable APK")
            data = archive.read(info)
            notice_entries.append({
                "path": name, "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
    return {
        "status": "JDK25_AGP_D8_ARM64_PASS_NOT_VENDOR_APPROVAL",
        "native_apk_paths": native,
        "native_jni_sha256": native_sha,
        "notice_files_in_disposable_apk": notice_entries,
        "exact_m157_4_notice_auto_packaged": any(
            entry["sha256"] == "e5e1a734e1f1e73a0526a4f6ab857f26c4657eb5a70c4f4bc05c20c5444e1ec9"
            for entry in notice_entries
        ),
        "automatic_notice_packaging_is_not_compliance_proof": True,
        "dex_count": len(dex_paths),
        "dex_defines_peer_connection": True,
        "apk_bytes": path.stat().st_size,
        "jdk25_toolchain_used": True,
        "JNI_executed": False,
        "vendor_approved": False,
    }



def inspect_arm64_bundle(path: Path, *, expected_native_sha256: str | None = None) -> dict:
    """Inspect an isolated Android App Bundle; no bundletool execution or APK publication."""
    if not path.is_file() or path.stat().st_size > agp.MAX_APK:
        raise D8ResearchError("Missing or oversized disposable AAB")
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            names = [item.filename for item in entries]
            if len(names) > evidence.audit.MAX_ENTRIES or len(names) != len(set(names)):
                raise D8ResearchError("Unexpected AAB entry inventory")
            native = sorted(
                name for name in names if name.startswith("base/lib/") and name.endswith(".so")
            )
            if not native or {name.split("/")[2] for name in native} != {RESEARCH_ABI}:
                raise D8ResearchError("Disposable AAB contains incorrect native ABI selection")
            if AAB_JNI_ENTRY not in native:
                raise D8ResearchError("ARM64 WebRTC JNI library missing from AAB")
            native_sha = sha256_native_member(archive, AAB_JNI_ENTRY)
            if expected_native_sha256 is not None and native_sha != expected_native_sha256:
                raise D8ResearchError("AAB JNI does not match exact pinned AAR ELF")
            dex = sorted(
                name for name in names if name.startswith("base/dex/classes") and name.endswith(".dex")
            )
            if not dex:
                raise D8ResearchError("Disposable AAB has no DEX files")
            if AAB_NOTICE_ENTRY not in names:
                raise D8ResearchError("Publisher NOTICE missing from disposable AAB")
            notice_info = archive.getinfo(AAB_NOTICE_ENTRY)
            if notice_info.file_size != NOTICE_BYTES:
                raise D8ResearchError("Publisher NOTICE AAB length mismatch")
            with archive.open(notice_info) as stream:
                notice = stream.read(NOTICE_BYTES + 1)
            if len(notice) != NOTICE_BYTES or hashlib.sha256(notice).hexdigest() != NOTICE_SHA256:
                raise D8ResearchError("Publisher NOTICE AAB SHA-256 mismatch")
    except (zipfile.BadZipFile, OSError, RuntimeError) as error:
        raise D8ResearchError("Invalid disposable AAB archive") from error
    return {
        "native_aab_paths": native,
        "native_jni_sha256": native_sha,
        "dex_count": len(dex),
        "verified_notice_aab_path": AAB_NOTICE_ENTRY,
        "verified_notice_aab_sha256": NOTICE_SHA256,
        "aab_bytes": path.stat().st_size,
        "vendor_approved": False,
        "JNI_executed": False,
        "bundletool_or_device_test_executed": False,
    }



def verify_pinned_bundletool(jar: Path) -> None:
    if not jar.is_file() or jar.stat().st_size != BUNDLETOOL_BYTES:
        raise D8ResearchError("Missing or unpinned bundletool toolchain")
    with jar.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != BUNDLETOOL_SHA256:
        raise D8ResearchError("bundletool SHA-256 mismatch")


def inspect_device_apk_set(path: Path, *, sdk: int,
                           expected_native_sha256: str | None = None) -> dict:
    """Validate actual device-targeted bundletool split APK payloads, without installation."""
    if sdk not in DEVICE_SDKS:
        raise D8ResearchError("Unreviewed Android API profile")
    if not path.is_file() or path.stat().st_size > MAX_APK_SET_BYTES:
        raise D8ResearchError("Missing or oversized bundletool APK set")
    notices = []
    natives = []
    native_shas = []
    dex_count = 0
    apk_names = []
    try:
        with zipfile.ZipFile(path) as outer:
            infos = outer.infolist()
            names = [info.filename for info in infos]
            if len(names) > evidence.audit.MAX_ENTRIES or len(names) != len(set(names)):
                raise D8ResearchError("Unsafe bundletool APK set inventory")
            for info in infos:
                if not info.filename.endswith(".apk"):
                    continue
                if not info.filename.startswith(("splits/", "standalones/")):
                    raise D8ResearchError("Unexpected bundletool APK member path")
                if info.file_size > MAX_SPLIT_APK_BYTES:
                    raise D8ResearchError("Oversized bundletool APK member")
                apk_names.append(info.filename)
                with outer.open(info) as stream:
                    payload = stream.read(MAX_SPLIT_APK_BYTES + 1)
                if len(payload) != info.file_size:
                    raise D8ResearchError("Truncated bundletool split APK")
                with zipfile.ZipFile(io.BytesIO(payload)) as apk:
                    entries = apk.infolist()
                    members = [item.filename for item in entries]
                    if len(members) > evidence.audit.MAX_ENTRIES or len(members) != len(set(members)):
                        raise D8ResearchError("Unsafe delivered APK entry inventory")
                    for member in entries:
                        name = member.filename
                        if name.startswith("lib/") and name.endswith(".so"):
                            natives.append(name)
                            native_shas.append(sha256_native_member(apk, name))
                        if name.startswith("classes") and name.endswith(".dex"):
                            dex_count += 1
                        if name.lower() == "notice" or name.lower().endswith("/notice"):
                            if member.file_size > 2 * 1024 * 1024:
                                raise D8ResearchError("Oversized split APK notice")
                            with apk.open(member) as notice_stream:
                                data = notice_stream.read(2 * 1024 * 1024 + 1)
                            notices.append((name, len(data), hashlib.sha256(data).hexdigest()))
    except (zipfile.BadZipFile, OSError, RuntimeError) as error:
        raise D8ResearchError("Invalid bundletool APK set archive") from error
    expected = "lib/arm64-v8a/libjingle_peerconnection_so.so"
    if not apk_names or expected not in natives or (
        any(not name.startswith("lib/arm64-v8a/") for name in natives)
    ):
        raise D8ResearchError("Device-targeted APK set JNI/ABI mismatch")
    if natives.count(expected) != 1:
        raise D8ResearchError("Device-targeted APK set duplicates JNI")
    if expected_native_sha256 is not None and native_shas != [expected_native_sha256]:
        raise D8ResearchError("Split APK JNI does not match exact pinned AAR ELF")
    if dex_count < 1:
        raise D8ResearchError("Device-targeted APK set has no DEX")
    if notices != [("assets/legal/NOTICE", NOTICE_BYTES, NOTICE_SHA256)]:
        raise D8ResearchError("Exact publisher NOTICE not delivered in split APKs")
    return {
        "status": "DEVICE_TARGETED_SPLIT_CONTENT_PASS_NOT_RUNTIME_APPROVAL",
        "device_sdk": sdk,
        "device_abi": RESEARCH_ABI,
        "split_apk_count": len(apk_names),
        "verified_notice_apk_path": "assets/legal/NOTICE",
        "verified_notice_sha256": NOTICE_SHA256,
        "native_lib_paths": sorted(natives),
        "native_jni_sha256": native_shas[0],
        "dex_count": dex_count,
        "jni_executed": False,
        "device_installed": False,
        "vendor_approved": False,
    }


def inspect_device_delivery(bundle: Path, *, tool: Path, root: Path,
                            expected_native_sha256: str,
                            runner=subprocess.run) -> list[dict]:
    verify_pinned_bundletool(tool)
    reports = []
    for sdk in DEVICE_SDKS:
        spec = root / f"android-{sdk}-arm64.json"
        spec.write_text(json.dumps({
            "supportedAbis": [RESEARCH_ABI],
            "supportedLocales": ["en"],
            "screenDensity": 420,
            "sdkVersion": sdk,
        }), encoding="utf-8")
        output = root / f"android-{sdk}-arm64.apks"
        try:
            completed = runner([
                "java", "-jar", str(tool.resolve()), "build-apks",
                "--bundle=" + str(bundle.resolve()),
                "--output=" + str(output.resolve()),
                "--device-spec=" + str(spec.resolve()),
                "--mode=default",
            ], cwd=root, check=False, timeout=180)
        except subprocess.TimeoutExpired as error:
            raise D8ResearchError("Pinned bundletool timed out") from error
        if completed.returncode != 0:
            raise D8ResearchError("Pinned bundletool failed for SDK " + str(sdk))
        reports.append(inspect_device_apk_set(
            output, sdk=sdk, expected_native_sha256=expected_native_sha256
        ))
    return reports


def collect(wrapper: Path, *, downloader=evidence.download_snapshot,
            runner=subprocess.run, tag: str = m157.TAG,
            bundletool: Path | None = None) -> dict:
    if not wrapper.is_file():
        raise D8ResearchError("Gradle wrapper missing")
    with tempfile.TemporaryDirectory(prefix="kenato-m157-jdk25-d8-") as tmp:
        base = Path(tmp)
        vendor = base / "m157.aar"
        url, _size, _sha, _producer, _source = m157.candidate(tag)
        digest, size = downloader(url, vendor, max_bytes=m157.MAX_BYTES)
        m157.verify_observation(digest, size, tag=tag)
        m157.inspect_pinned_aar(vendor, tag=tag)
        with zipfile.ZipFile(vendor) as archive:
            pinned_native_sha = sha256_native_member(
                archive, "jni/arm64-v8a/libjingle_peerconnection_so.so"
            )
        root = base / "disposable"
        write_arm64_probe(root, vendor)
        try:
            result = runner([str(wrapper.resolve()), "--no-daemon", "--stacktrace",
                             ":app:assembleDebug"],
                            cwd=root, check=False, timeout=540)
        except subprocess.TimeoutExpired as error:
            raise D8ResearchError("Disposable AGP D8 build timed out") from error
        if result.returncode != 0:
            raise D8ResearchError("Disposable AGP D8 build failed")
        apk = root / "app/build/outputs/apk/debug/app-debug.apk"
        report = inspect_arm64_apk(apk, expected_native_sha256=pinned_native_sha)
        if tag == m157.PATCH_TAG:
            if bundletool is None:
                raise D8ResearchError("Pinned bundletool required for patched AAB delivery research")
            verify_pinned_bundletool(bundletool)
            if report["exact_m157_4_notice_auto_packaged"]:
                raise D8ResearchError("Expected negative automatic NOTICE packaging baseline changed")
            # Prove that an explicitly included exact generated NOTICE survives
            # AGP packaging. This disposable build does not provide a legal UI.
            include_reviewed_notice_asset(root, vendor)
            try:
                followup = runner([str(wrapper.resolve()), "--no-daemon", "--stacktrace",
                                  ":app:assembleDebug", ":app:bundleDebug"],
                                 cwd=root, check=False, timeout=540)
            except subprocess.TimeoutExpired as error:
                raise D8ResearchError("Explicit NOTICE disposable build timed out") from error
            if followup.returncode != 0:
                raise D8ResearchError("Disposable NOTICE packaging build failed")
            packaged = inspect_arm64_apk(
                apk, expected_native_sha256=pinned_native_sha
            )
            if not packaged["exact_m157_4_notice_auto_packaged"] or (
                packaged["native_apk_paths"] != report["native_apk_paths"]
                or packaged["dex_count"] != report["dex_count"]
            ):
                raise D8ResearchError("Explicit publisher NOTICE packaging not reproducible")
            bundle = inspect_arm64_bundle(
                root / "app/build/outputs/bundle/debug/app-debug.aab",
                expected_native_sha256=pinned_native_sha
            )
            if (
                [name.removeprefix("base/") for name in bundle["native_aab_paths"]]
                != packaged["native_apk_paths"]
                or bundle["dex_count"] != packaged["dex_count"]
            ):
                raise D8ResearchError("AAB and APK JNI/DEX inventories differ")
            report["publisher_notice_explicit_asset_aab_path"] = bundle["verified_notice_aab_path"]
            report["publisher_notice_explicit_asset_aab_sha256"] = bundle["verified_notice_aab_sha256"]
            report["publisher_notice_explicit_asset_aab_bytes"] = bundle["aab_bytes"]
            report["device_targeted_apk_sets"] = inspect_device_delivery(
                root / "app/build/outputs/bundle/debug/app-debug.aab",
                tool=bundletool, root=root, runner=runner,
                expected_native_sha256=pinned_native_sha
            )
            report["bundletool_executed"] = True
            report["device_test_executed"] = False
            report["publisher_notice_explicit_asset_included"] = True
            report["publisher_notice_explicit_asset_path"] = "assets/legal/NOTICE"
            report["publisher_notice_explicit_asset_apk_bytes"] = packaged["apk_bytes"]
            report["publisher_notice_automatically_included"] = False
            report["release_legal_ui_accessibility_verified"] = False
        report["pinned_original_aar_jni_sha256"] = pinned_native_sha
        report["publisher_tag"] = tag
        report["publisher_asset_sha256"] = digest
        report["producer_source_revision_UNVERIFIED_IN_BINARY"] = _source
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradlew", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tag", choices=(m157.TAG, m157.PATCH_TAG), default=m157.TAG)
    parser.add_argument("--bundletool", type=Path,
                        help="Locally verified exact bundletool 1.18.3 JAR for patched AAB only")
    options = parser.parse_args()
    try:
        result = collect(options.gradlew, tag=options.tag, bundletool=options.bundletool)
    except (D8ResearchError, m157.CandidateProbeError, evidence.EvidenceError,
            evidence.audit.AarAuditError, OSError, zipfile.BadZipFile) as error:
        result = {
            "status": "JDK25_D8_RESEARCH_BLOCKED",
            "publisher_tag": options.tag,
            "failure": type(error).__name__,
            "detail": str(error)[:160],
            "JNI_executed": False,
            "vendor_approved": False,
        }
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Shiguredo m157 JDK25 D8 research:", result["status"])
    if "failure" in result:
        print("Reason:", result["failure"], result["detail"])
    return 0 if result["status"] == "JDK25_AGP_D8_ARM64_PASS_NOT_VENDOR_APPROVAL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
