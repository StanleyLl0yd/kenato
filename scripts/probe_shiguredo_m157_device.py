#!/usr/bin/env python3
"""Isolated, permissionless ARM64 m157 device APK; build only, never execute JNI."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
import collect_webrtc_candidate_evidence as evidence
import probe_shiguredo_m157 as vendor
import probe_shiguredo_m157_d8 as d8

PACKAGE = "org.kenato.m5jnisentinel"
STATUS = "RESEARCH_APK_BUILT_DEVICE_NOT_TESTED"

JAVA = r"""package org.kenato.m5jnisentinel;
import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.webrtc.PeerConnectionFactory;
public final class MainActivity extends Activity {
  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    LinearLayout layout = new LinearLayout(this);
    layout.setOrientation(LinearLayout.VERTICAL);
    TextView output = new TextView(this);
    output.setText("NOT_EXECUTED - third-party native code unapproved");
    Button button = new Button(this);
    button.setText("Run local JNI smoke");
    button.setOnClickListener(view -> {
      button.setEnabled(false);
      output.setText("RUNNING");
      new Thread(() -> {
        String status;
        try {
          PeerConnectionFactory.InitializationOptions opts =
              PeerConnectionFactory.InitializationOptions.builder(
                  getApplicationContext()).createInitializationOptions();
          PeerConnectionFactory.initialize(opts);
          PeerConnectionFactory factory =
              PeerConnectionFactory.builder().createPeerConnectionFactory();
          if (factory == null) {
            status = "E_NULL_FACTORY";
          } else {
            factory.dispose();
            status = "PASS_JNI_FACTORY_DISPOSE";
          }
        } catch (UnsatisfiedLinkError error) {
          status = "E_LINK";
        } catch (NoClassDefFoundError error) {
          status = "E_CLASS";
        } catch (ExceptionInInitializerError error) {
          status = "E_INIT";
        } catch (Throwable error) {
          status = "E_OTHER";
        }
        final String result = status;
        runOnUiThread(() -> output.setText(result));
      }, "m5-test-only-jni").start();
    });
    layout.addView(output);
    layout.addView(button);
    setContentView(layout);
  }
}
"""
MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:label="M5 JNI research" android:allowBackup="false"
               android:usesCleartextTraffic="false">
    <activity android:name="org.kenato.m5jnisentinel.MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
    </activity>
  </application>
</manifest>
"""


class DeviceProbeError(ValueError):
    pass


def write_device_probe(root: Path, aar: Path) -> None:
    d8.write_arm64_probe(root, aar)
    source = root / "app/src/main/java/org/kenato/m5jnisentinel/MainActivity.java"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(JAVA, encoding="utf-8")
    (root / "app/src/main/AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    gradle = root / "app/build.gradle"
    original = gradle.read_text(encoding="utf-8")
    marker = "applicationId 'org.kenato.research'"
    if original.count(marker) != 1:
        raise DeviceProbeError("Unrecognized disposable application identity")
    gradle.write_text(original.replace(marker, "applicationId '" + PACKAGE + "'"),
                      encoding="utf-8")


def audit_manifest(apk: Path, *, sdk: str | None = None, runner=subprocess.run) -> None:
    sdk = sdk if sdk is not None else os.environ.get("ANDROID_HOME", "")
    aapt2 = Path(sdk) / "build-tools/37.0.0/aapt2"
    if not sdk or not aapt2.is_file():
        raise DeviceProbeError("Pinned SDK37 aapt2 unavailable")
    try:
        output = runner([str(aapt2), "dump", "xmltree", str(apk), "--file", "AndroidManifest.xml"],
                        capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DeviceProbeError("Merged manifest audit failed") from error
    if output.returncode or not isinstance(output.stdout, bytes) or len(output.stdout) > 512 * 1024:
        raise DeviceProbeError("Merged manifest audit did not complete")
    text = output.stdout.decode("utf-8", errors="replace")
    if re.search(r"(?m)^\s*E:\s*uses-permission(?:-sdk-\d+)?\b", text):
        raise DeviceProbeError("Merged manifest requested Android permissions")
    if PACKAGE + ".MainActivity" not in text:
        raise DeviceProbeError("Expected research activity missing from APK")


def audit_apk_16k_zip_alignment(apk: Path, *, sdk: str | None = None,
                                runner=subprocess.run) -> None:
    """Official Android zipalign verification: never alter/re-sign test APK."""
    sdk = sdk if sdk is not None else os.environ.get("ANDROID_HOME", "")
    binary = Path(sdk) / "build-tools/37.0.0/zipalign"
    if not sdk or not binary.is_file():
        raise DeviceProbeError("Pinned SDK37 zipalign unavailable")
    try:
        check = runner([str(binary), "-c", "-P", "16", "-v", "4", str(apk)],
                       capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DeviceProbeError("16KiB APK ZIP alignment audit could not run") from error
    if (check.returncode != 0 or not isinstance(check.stdout, bytes) or
            len(check.stdout) > 256 * 1024 or
            b"Verification successful" not in check.stdout):
        raise DeviceProbeError("APK ZIP native library is not 16KiB aligned")


def build(wrapper: Path, apk_output: Path | None, *, downloader=evidence.download_snapshot,
          runner=subprocess.run) -> dict:
    if not wrapper.is_file():
        raise DeviceProbeError("Gradle wrapper missing")
    with tempfile.TemporaryDirectory(prefix="kenato-m157-device-") as directory:
        base = Path(directory)
        aar = base / "m157.aar"
        digest, size = downloader(vendor.RELEASE_URL, aar, max_bytes=vendor.MAX_BYTES)
        vendor.verify_observation(digest, size)
        if aar.stat().st_size != size:
            raise DeviceProbeError("AAR changed before verification")
        vendor.inspect_pinned_aar(aar)
        app = base / "disposable"
        write_device_probe(app, aar)
        try:
            result = runner([str(wrapper.resolve()), "--no-daemon", "--stacktrace",
                             ":app:assembleDebug"], cwd=app, check=False, timeout=540)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DeviceProbeError("Physical JNI smoke APK build failed") from error
        if result.returncode:
            raise DeviceProbeError("Physical JNI smoke Gradle build failure")
        apk = app / "app/build/outputs/apk/debug/app-debug.apk"
        d8.inspect_arm64_apk(apk)
        audit_manifest(apk)
        audit_apk_16k_zip_alignment(apk)
        sha = hashlib.sha256(apk.read_bytes()).hexdigest()
        if apk_output is not None:
            apk_output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(apk, apk_output)
            if hashlib.sha256(apk_output.read_bytes()).hexdigest() != sha:
                raise DeviceProbeError("Copied APK SHA256 mismatch")
        return {
            "status": STATUS, "apk_sha256": sha, "apk_bytes": apk.stat().st_size,
            "application_id": PACKAGE, "arm64_only": True, "no_permissions": True,
            "native_apk_zip_alignment_16k_verified": True,
            "jni_executed": False, "microphone_executed": False,
            "vendor_approved_for_kenato": False, "production_release": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradlew", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--device-apk", type=Path)
    args = parser.parse_args()
    try:
        report = build(args.gradlew, args.device_apk)
        code = 0
    except (DeviceProbeError, OSError, vendor.CandidateProbeError,
            evidence.EvidenceError, evidence.audit.AarAuditError, d8.D8ResearchError) as error:
        report = {"status": "DEVICE_BUILD_BLOCKED", "error_type": type(error).__name__,
                  "reason": str(error)[:160], "jni_executed": False,
                  "vendor_approved_for_kenato": False}
        code = 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("M5 isolated JNI device build:", report["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
