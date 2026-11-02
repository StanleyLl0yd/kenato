#!/usr/bin/env python3
"""Windows physical-acceptance helper regression using a synthetic ADB on Linux CI.

This is NOT a real Android device run; never count it as physical acceptance.
Requires pwsh, present on the pinned GitHub ubuntu-24.04 image.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/Run-KenatoM5DispatchProbe.ps1"
HEAD_SHA = "a" * 40
CHECKOUT_SHA = "b" * 40
FAKE_ADB = """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "devices" ]]; then
  printf 'List of devices attached\\nmock-qa-phone\\tdevice\\n'
  exit 0
fi
[[ "${1:-}" == "-s" && "${2:-}" == "mock-qa-phone" ]] || exit 17
shift 2
case "$*" in
  'shell getprop ro.build.version.sdk') echo 34 ;;
  'shell getprop ro.build.version.release') echo 14 ;;
  'shell getprop ro.build.version.security_patch') echo 2026-10-01 ;;
  'shell getprop ro.kernel.qemu') echo "${ADB_TEST_EMULATOR:-0}" ;;
  'shell pm path com.sl.kenato') echo package:/dev/synthetic-production.apk ;;
  'shell pm path com.sl.kenato.m5dispatchprobe') echo package:/dev/synthetic-probe.apk ;;
  'shell pm path com.sl.kenato.m5dispatchprobe.test') echo package:/dev/synthetic-tests.apk ;;
  'install -r -t '*) echo Success ;;
  'shell am instrument -w -r -e class '*) 
    if [[ "${ADB_TEST_INSTRUMENT_FAIL:-0}" == 1 ]]; then
      echo 'FAILURES!!!'
      echo 'Tests run: 5,  Failures: 1'
    else
      echo 'OK (5 tests)'
    fi
    ;;
  *) echo 'UNEXPECTED SYNTHETIC ADB INVOCATION' >&2; exit 18 ;;
esac
"""

def prepare_artifact(location: Path) -> None:
    members = {
        "app-m5DispatchProbe.apk": b"synthetic debug app; no Android executable",
        "app-m5DispatchProbe-androidTest.apk": b"synthetic instrumentation; no Android executable",
    }
    (location / "artifact").mkdir()
    sums = []
    for name, content in members.items():
        (location / "artifact" / name).write_bytes(content)
        sums.append(f"{hashlib.sha256(content).hexdigest()}  {name}")
    (location / "artifact" / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    (location / "artifact" / "SCOPE.txt").write_text(
        f"checked_out_sha={CHECKOUT_SHA}\n"
        f"pr_head_sha={HEAD_SHA}\n"
        "application_id=com.sl.kenato.m5dispatchprobe\n"
        "status=research_only_no_device_pass_no_voice\n"
        "not_a_release=true\n"
    )
    with zipfile.ZipFile(location / "diagnostic.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in sorted((location / "artifact").iterdir()):
            archive.write(entry, arcname=entry.name)
    (location / "bin").mkdir()
    mock = location / "bin" / "adb"
    mock.write_text(FAKE_ADB)
    mock.chmod(0o700)


def execute(
    folder: Path, *, expected_head: str = HEAD_SHA,
    expected_zip_sha: str | None = None, **environ: str
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    if expected_zip_sha is None:
        expected_zip_sha = hashlib.sha256((folder / "diagnostic.zip").read_bytes()).hexdigest()
    environment["PATH"] = str(folder / "bin") + os.pathsep + environment["PATH"]
    environment.update(environ)
    return subprocess.run(
        [
            "pwsh", "-NoProfile", "-File", str(SCRIPT),
            "-ArtifactZip", str(folder / "diagnostic.zip"),
            "-ExpectedArtifactZipSha256", expected_zip_sha,
            "-ExpectedHeadSha", expected_head,
            "-EvidenceDirectory", str(folder / "evidence"),
        ],
        text=True,
        capture_output=True,
        env=environment,
        timeout=30,
    )


with tempfile.TemporaryDirectory(prefix="kenato-m5-fake-adb-") as temp:
    folder = Path(temp)
    prepare_artifact(folder)
    success = execute(folder)
    if success.returncode != 0:
        raise SystemExit(f"Sanitized device-acceptance helper failed mock PASS:\n{success.stderr}")
    recorded = list((folder / "evidence").glob("*.json"))
    assert len(recorded) == 1, "Expected exactly one sanitized evidence file"
    evidence = json.loads(recorded[0].read_text(encoding="utf-8-sig"))
    assert evidence["result"] == "PASS"
    assert evidence["passed_expected"] == 5
    assert evidence["android_api"] == 34
    assert evidence["reviewed_pr_head_sha"] == HEAD_SHA
    assert evidence["artifact_zip_sha256"] == hashlib.sha256(
        (folder / "diagnostic.zip").read_bytes()
    ).hexdigest()
    assert len(evidence["serial_sha256_prefix"]) == 12
    for forbidden in ("mock-qa-phone", "package:/dev/", "private", "ciphertext"):
        assert forbidden not in recorded[0].read_text(), f"Evidence leak: {forbidden}"

with tempfile.TemporaryDirectory(prefix="kenato-m5-fake-adb-") as temp:
    folder = Path(temp)
    prepare_artifact(folder)
    emulator = execute(folder, ADB_TEST_EMULATOR="1")
    assert emulator.returncode != 0, "Emulator must not satisfy physical acceptance"
    assert not (folder / "evidence").exists()

with tempfile.TemporaryDirectory(prefix="kenato-m5-fake-adb-") as temp:
    folder = Path(temp)
    prepare_artifact(folder)
    failed = execute(folder, ADB_TEST_INSTRUMENT_FAIL="1")
    assert failed.returncode != 0, "A failed instrumented suite must fail closed"
    recorded = list((folder / "evidence").glob("*.json"))
    assert len(recorded) == 1
    assert json.loads(recorded[0].read_text(encoding="utf-8-sig"))["result"] == "FAIL"

with tempfile.TemporaryDirectory(prefix="kenato-m5-fake-adb-") as temp:
    folder = Path(temp)
    prepare_artifact(folder)
    mismatched = execute(folder, expected_head="c" * 40)
    assert mismatched.returncode != 0, "Mismatched PR HEAD must fail before installation"
    assert not (folder / "evidence").exists()


with tempfile.TemporaryDirectory(prefix="kenato-m5-fake-adb-") as temp:
    folder = Path(temp)
    prepare_artifact(folder)
    verified = hashlib.sha256((folder / "diagnostic.zip").read_bytes()).hexdigest()
    with (folder / "diagnostic.zip").open("ab") as output:
        output.write(b"whole-archive-substitution")
    substituted = execute(folder, expected_zip_sha=verified)
    assert substituted.returncode != 0, "Substituted Actions ZIP must fail before ADB"
    assert "does not match" in substituted.stderr
    assert not (folder / "evidence").exists()

print("M5 dispatch simulated ADB operator-script regressions PASS (NOT physical device evidence)")
