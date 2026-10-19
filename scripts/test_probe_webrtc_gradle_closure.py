#!/usr/bin/env python3
"""No-network official-coordinate dependency graph and artifact tests."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import probe_webrtc_gradle_closure as closure


class ClosureTests(unittest.TestCase):
    def test_modules_are_bounded_and_require_exact_coordinate(self):
        gav = closure.COORDINATES["m149_maven"]
        out = "+--- " + gav + "\n\\--- org.jetbrains.kotlin:kotlin-stdlib:2.2.10\n"
        self.assertIn("org.jetbrains.kotlin:kotlin-stdlib:2.2.10",
                      closure.resolved_modules(out, gav))
        with self.assertRaisesRegex(closure.ClosureError, "absent"):
            closure.resolved_modules("No dependencies", gav)

    def test_artifact_requires_exact_sha_and_one_primary_aar(self):
        gav = closure.COORDINATES["m150_maven"]
        digest = "a" * 64
        record = "KENATO_ARTIFACT " + gav + " android-150.7871.01.aar " + digest + " 49147033"
        result = closure.resolved_artifacts(record, gav, digest)
        self.assertEqual(digest, result[0]["sha256"])
        with self.assertRaisesRegex(closure.ClosureError, "differs"):
            closure.resolved_artifacts(record, gav, "b" * 64)
        with self.assertRaisesRegex(closure.ClosureError, "differs"):
            closure.resolved_artifacts(record + "\n" + record, gav, digest)
        with self.assertRaisesRegex(closure.ClosureError, "Missing"):
            closure.resolved_artifacts("No artifacts", gav, digest)

    def test_temporary_official_dependency_replaces_local_aar(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            closure.build_project(root, closure.COORDINATES["m149_maven"])
            text = (root / "app/build.gradle").read_text()
            self.assertIn("implementation 'im.conversations.webrtc:webrtc-android:149.0.0'", text)
            self.assertNotIn("implementation files(", text)
            self.assertFalse((root / "candidate.aar").exists())
            self.assertIn("resolvedConfiguration.resolvedArtifacts", text)

    def test_failure_is_recorded_without_approval(self):
        def reject(*_args, **_kwargs):
            return type("Result", (), {"returncode": 7, "stdout": "failed"})()
        result, complete = closure.collect(Path("/repo/gradlew"), runner=reject)
        self.assertFalse(complete)
        self.assertFalse(result["vendor_approved"])
        self.assertEqual(2, len(result["results"]))
        self.assertTrue(all(
            x["status"] == "CLOSURE_PROBE_FAILED" for x in result["results"].values()
        ))


if __name__ == "__main__":
    unittest.main()
