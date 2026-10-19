#!/usr/bin/env python3
"""Isolated official-coordinate Gradle resolution probe; never enable vendor code."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import probe_webrtc_agp as agp

COORDINATES = {
    "m149_maven": "im.conversations.webrtc:webrtc-android:149.0.0",
    "m150_maven": "io.github.webrtc-sdk:android:150.7871.01",
}
MODULE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9_.-]*:[a-zA-Z0-9_.-]+:[0-9][a-zA-Z0-9_.+-]*)")
ARTIFACT = re.compile(
    r"^KENATO_ARTIFACT ([a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+:[0-9a-zA-Z_.+-]+) "
    r"([^/\s]+) ([0-9a-f]{64}) ([0-9]+)$"
)
MAX_ARTIFACTS = 64

# Gradle's resolved artifact hash is checked against separately observed M5
# CI bytes. This does not authenticate the Maven publisher's signing identity.
GRADLE_REPORT_TASK = r"""
tasks.register("kenatoReportArtifacts") {
  doLast {
    def artifacts = project.configurations.getByName("debugRuntimeClasspath")
      .resolvedConfiguration.resolvedArtifacts
    if (artifacts.size() > 64) {
      throw new GradleException("Too many resolved artifacts for bounded M5 probe")
    }
    artifacts.each { artifact ->
      def file = artifact.file
      if (!file.isFile() || file.length() > 250L * 1024L * 1024L) {
        throw new GradleException("Missing or oversized resolved artifact")
      }
      def digest = java.security.MessageDigest.getInstance("SHA-256")
      file.withInputStream { stream ->
        byte[] buffer = new byte[128 * 1024]
        int bytesRead
        while ((bytesRead = stream.read(buffer)) != -1) {
          digest.update(buffer, 0, bytesRead)
        }
      }
      def id = artifact.moduleVersion.id
      println("KENATO_ARTIFACT " + id.group + ":" + id.name + ":" + id.version
          + " " + file.name + " " + digest.digest().encodeHex().toString()
          + " " + file.length())
    }
  }
}
"""


class ClosureError(ValueError):
    """Official-coordinate resolution did not match research expectations."""


def build_project(root: Path, coordinate: str) -> None:
    # Reuse exact AGP 9.4 / Gradle-9.7 / SDK-37 probe shape already approved
    # for research. Its temporary file AAR is deliberately deleted here.
    temp_fixture = root.parent / "unused-placeholder.aar"
    temp_fixture.write_bytes(b"placeholder never used by Gradle")
    agp.write_disposable_app(root, temp_fixture)
    (root / "candidate.aar").unlink()
    temp_fixture.unlink()
    path = root / "app/build.gradle"
    text = path.read_text(encoding="utf-8")
    old = "dependencies { implementation files('../candidate.aar') }"
    if text.count(old) != 1:
        raise ClosureError("Unexpected base research build definition")
    path.write_text(
        text.replace(old, "dependencies { implementation '" + coordinate + "' }")
        + GRADLE_REPORT_TASK, encoding="utf-8",
    )


def resolved_modules(output: str, coordinate: str) -> list[str]:
    modules = sorted(set(MODULE.findall(output)))
    if coordinate not in modules:
        raise ClosureError("Expected Maven coordinate absent from Gradle dependency graph")
    return modules[:256]


def resolved_artifacts(output: str, coordinate: str, digest: str) -> list[dict]:
    results = []
    for line in output.splitlines():
        match = ARTIFACT.fullmatch(line.strip())
        if match:
            module, filename, sha, size = match.groups()
            results.append({
                "module": module, "filename": filename, "sha256": sha,
                "bytes": int(size),
            })
    if not results or len(results) > MAX_ARTIFACTS:
        raise ClosureError("Missing or unbounded Gradle artifact inventory")
    primary = [x for x in results if x["module"] == coordinate
               and x["filename"].endswith(".aar")]
    if len(primary) != 1 or primary[0]["sha256"] != digest:
        raise ClosureError("Resolved primary Maven AAR differs from previously observed snapshot")
    return sorted(results, key=lambda item: (item["module"], item["filename"]))


def gradle_command(wrapper: Path, root: Path, args: list[str], *,
                   runner=subprocess.run) -> str:
    try:
        completed = runner(
            [str(wrapper), "--no-daemon", "--console=plain", *args],
            cwd=root, check=False, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=600,
        )
    except subprocess.TimeoutExpired as exc:
        raise ClosureError("Official-coordinate Gradle probe timed out") from exc
    if completed.returncode != 0:
        print((completed.stdout or "")[-4000:], file=sys.stderr)
        raise ClosureError(f"Official-coordinate Gradle task failed (exit={completed.returncode})")
    return completed.stdout


def probe_one(wrapper: Path, root: Path, label: str, *,
              runner=subprocess.run) -> dict:
    gav = COORDINATES[label]
    build_project(root, gav)
    dependency_output = gradle_command(
        wrapper, root, [":app:dependencies", "--configuration", "debugRuntimeClasspath"],
        runner=runner,
    )
    modules = resolved_modules(dependency_output, gav)
    if label == "m149_maven" and not any(
        item.startswith("org.jetbrains.kotlin:kotlin-stdlib:") for item in modules
    ):
        raise ClosureError("Expected m149 Kotlin stdlib dependency absent in Gradle closure")
    artifact_output = gradle_command(
        wrapper, root, [":app:kenatoReportArtifacts"], runner=runner,
    )
    artifacts = resolved_artifacts(artifact_output, gav, agp.EXPECTED[label])
    # The official-coordinate build also runs real AGP/D8, unlike a POM-only audit.
    build_output = gradle_command(
        wrapper, root, [":app:assembleDebug"], runner=runner,
    )
    del build_output
    packaged = agp.inspect_apk(
        root / "app/build/outputs/apk/debug/app-debug.apk"
    )
    return {
        "coordinate": gav,
        "resolved_modules": modules,
        "resolved_artifacts": artifacts,
        "android_dex_and_abi": packaged,
        "status": "OFFICIAL_GRADLE_CLOSURE_OBSERVED_NOT_VENDOR_APPROVAL",
        "publisher_authenticated": False,
    }


def collect(wrapper: Path, *, runner=subprocess.run) -> tuple[dict, bool]:
    report = {
        "status": "M5_OFFICIAL_COORDINATE_RESEARCH_ONLY",
        "vendor_approved": False,
        "production_dependencies_changed": False,
        "resolved_publisher_identity_independently_authenticated": False,
        "results": {},
        "missing_gates": [
            "independent Maven publisher signature/provenance verification",
            "native GN flags/source/reproducibility and complete license/CVE audit",
            "Android 10/13/14+ JNI runtime and P01-P24 physical acceptance",
        ],
    }
    passed = True
    with tempfile.TemporaryDirectory(prefix="kenato-m5-maven-") as directory:
        root = Path(directory)
        for label in COORDINATES:
            try:
                report["results"][label] = probe_one(
                    wrapper, root / label, label, runner=runner,
                )
            except (ClosureError, agp.ProbeError, OSError) as exc:
                report["results"][label] = {
                    "status": "CLOSURE_PROBE_FAILED",
                    "failure_type": type(exc).__name__,
                    "failure_reason": str(exc)[:160],
                    "vendor_approved": False,
                }
                passed = False
    return report, passed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradlew", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.gradlew.is_file():
        parser.error("Gradle wrapper not found")
    result, passed = collect(args.gradlew.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print("Maven/Gradle closure research recorded; no vendor was approved.")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
