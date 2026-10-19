#!/usr/bin/env python3
"""Synthetic non-network tests of the pre-approval M5 media boundary."""
from __future__ import annotations

import unittest
import verify_m5_media_boundary as gate


def baseline():
    return {
        "settings.gradle.kts": b"pluginManagement { repositories { google() } }",
        "build.gradle.kts": b"plugins {}",
        "android/app/build.gradle.kts": b"dependencies { implementation(libs.okhttp) }",
        "gradle/libs.versions.toml": b'[libraries]\nokhttp = { module = "com.squareup.okhttp3:okhttp" }\n',
        "android/app/src/main/AndroidManifest.xml": (
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            b'<uses-permission android:name="android.permission.INTERNET"/>'
            b'<application android:usesCleartextTraffic="false"/></manifest>'
        ),
        "Makefile": b"python3 scripts/verify_m5_media_boundary.py",
        ".github/workflows/ci.yml": b"python3 scripts/verify_m5_media_boundary.py",
        ".github/workflows/release-android.yml": (
            b"python3 scripts/verify_m5_media_boundary.py\n"
            b"      - name: Restore and validate release keystore\n"
        ),
    }


class BoundaryTests(unittest.TestCase):
    def test_clean_source_passes(self):
        self.assertEqual([], gate.inspect(baseline()))

    def test_catches_maven_coordinate_even_with_an_alias(self):
        state = baseline()
        state["gradle/libs.versions.toml"] += b'x = { module = "io.github.webrtc-sdk:android", version = "150.7871.01" }'
        self.assertTrue(any("libs.versions.toml" in e for e in gate.inspect(state)))

    def test_catches_direct_gradle_vendor_reference(self):
        state = baseline()
        state["android/app/build.gradle.kts"] += b'\nimplementation("im.conversations.webrtc:webrtc-android:149.0.0")'
        self.assertTrue(any("dependency" in e for e in gate.inspect(state)))

    def test_catches_mic_in_main_or_variant_overlay(self):
        for path in ("android/app/src/main/AndroidManifest.xml",
                     "android/app/src/release/AndroidManifest.xml"):
            state = baseline()
            state[path] = (b'<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                           b'<uses-permission android:name="android.permission.RECORD_AUDIO"/>'
                           b'</manifest>')
            self.assertTrue(any("microphone permission" in e for e in gate.inspect(state)))

    def test_catches_mic_service_even_without_permission(self):
        state = baseline()
        state["android/app/src/main/AndroidManifest.xml"] = (
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            b'<application><service android:foregroundServiceType="dataSync|microphone"/></application>'
            b'</manifest>'
        )
        self.assertTrue(any("foreground service" in e for e in gate.inspect(state)))

    def test_catches_vendor_runtime_source(self):
        for variant in ("main", "release", "debug"):
            state = baseline()
            state[f"android/app/src/{variant}/java/Media.kt"] = b"package com.sl.kenato\nimport org.webrtc.PeerConnection"
            self.assertTrue(any("JNI source" in e for e in gate.inspect(state)))

    def test_catches_prepackaged_aar_and_so(self):
        for path in ("android/app/src/main/assets/media.aar",
                     "android/app/src/main/jniLibs/arm64-v8a/libmedia.so"):
            state = baseline()
            state[path] = b"binary"
            self.assertTrue(any("vendored" in e for e in gate.inspect(state)))

    def test_missing_input_and_missing_wiring_fail_closed(self):
        state = baseline()
        del state["android/app/src/main/AndroidManifest.xml"]
        self.assertTrue(any("AndroidManifest.xml" in e for e in gate.inspect(state)))
        state = baseline()
        del state[".github/workflows/ci.yml"]
        self.assertTrue(any("ci.yml" in e for e in gate.inspect(state)))
        state = baseline()
        state["Makefile"] = b"test-security: echo bypassed"
        self.assertTrue(any("Makefile" in e for e in gate.inspect(state)))

    def test_guard_must_run_before_signer_material(self):
        state = baseline()
        state[".github/workflows/release-android.yml"] = (
            b"      - name: Restore and validate release keystore\n"
            b"python3 scripts/verify_m5_media_boundary.py\n"
        )
        self.assertTrue(any("precede signing" in e for e in gate.inspect(state)))

    def test_bad_manifest_and_entity_declaration_fail(self):
        for raw in (b"<manifest>", b'<!DOCTYPE a [ <!ENTITY x "something"> ]><manifest/>'):
            state = baseline()
            state["android/app/src/main/AndroidManifest.xml"] = raw
            self.assertTrue(any("manifest" in e for e in gate.inspect(state)))


if __name__ == "__main__":
    unittest.main()
