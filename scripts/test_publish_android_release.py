#!/usr/bin/env python3
"""Hermetic regression tests for ID-driven Android release publication."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "scripts" / "publish_android_release.sh"
SOURCE_SHA = "f83207ed619dfe4393867aa8689c0dce5780674f"
TAG = "v0.0.2"
REPO = "example/kenato"

FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["FAKE_RELEASE_STATE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
if not args or args[0] != "api":
    raise SystemExit("fake gh only supports api")

args = args[1:]
method = "GET"
jq_expr = None
endpoint = None
i = 0
while i < len(args):
    arg = args[i]
    if arg == "--method":
        method = args[i + 1]
        i += 2
        continue
    if arg == "--jq":
        jq_expr = args[i + 1]
        i += 2
        continue
    if arg in ("-f", "-F", "-H"):
        i += 2
        continue
    if endpoint is None and not arg.startswith("-"):
        endpoint = arg
    i += 1

if endpoint is None:
    raise SystemExit("missing endpoint")

sha = os.environ["GITHUB_SHA"]
tag = os.environ["RELEASE_TAG"]

def save():
    state_path.write_text(json.dumps(state))

def emit(value):
    if jq_expr is None:
        print(json.dumps(value))
        return
    mapping = {
        ".object.sha": value.get("object", {}).get("sha", ""),
        ".object.type": value.get("object", {}).get("type", ""),
        ".sha": value.get("sha", ""),
        ".draft": value.get("draft", ""),
    }
    result = mapping.get(jq_expr)
    if result is None:
        raise SystemExit(f"unsupported jq expression: {jq_expr}")
    if isinstance(result, bool):
        print("true" if result else "false")
    else:
        print(result)

if endpoint.endswith("/git/ref/heads/main"):
    emit({"object": {"sha": sha, "type": "commit"}})
elif endpoint.endswith(f"/git/ref/tags/{tag}"):
    if not state["tag_exists"]:
        raise SystemExit(1)
    emit({"object": {"sha": state["tag_sha"], "type": state["tag_type"]}})
elif endpoint.endswith(f"/commits/{tag}"):
    if not state["tag_exists"]:
        raise SystemExit(1)
    emit({"sha": state["tag_sha"]})
elif endpoint.endswith(f"/releases/tags/{tag}"):
    release = state.get("release")
    # Drafts are intentionally invisible here, matching the observed GITHUB_TOKEN behavior.
    if release is None or release["draft"]:
        raise SystemExit(1)
    emit(release)
elif endpoint.endswith("/releases") and method == "POST":
    if state.get("release") is not None:
        raise SystemExit("unexpected duplicate release creation")
    release = {
        "id": 42,
        "draft": True,
        "tag_name": tag,
        "target_commitish": sha,
        "published_at": None,
        "assets": [],
    }
    state["release"] = release
    save()
    emit(release)
elif endpoint.endswith("/releases/42") and method == "GET":
    release = state.get("release")
    if release is None:
        raise SystemExit(1)
    emit(release)
elif endpoint.endswith("/releases/42") and method == "DELETE":
    release = state.get("release")
    if release is None:
        raise SystemExit(1)
    if not release["draft"]:
        raise SystemExit("refusing to delete published release")
    state["release"] = None
    state["deleted"] = True
    save()
elif endpoint.endswith("/releases/42") and method == "PATCH":
    release = state.get("release")
    if release is None:
        raise SystemExit(1)
    release["draft"] = False
    release["published_at"] = "2026-09-21T00:00:00Z"
    state["tag_exists"] = True
    state["tag_sha"] = sha
    state["tag_type"] = "commit"
    save()
    emit(release)
else:
    raise SystemExit(f"unsupported fake gh request: {method} {endpoint}")
'''

FAKE_CURL = r'''#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

state_path = Path(os.environ["FAKE_RELEASE_STATE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
data_path = None
url = None
i = 0
while i < len(args):
    arg = args[i]
    if arg == "--data-binary":
        value = args[i + 1]
        if not value.startswith("@"):
            raise SystemExit("expected @file upload")
        data_path = Path(value[1:])
        i += 2
        continue
    if arg in ("--header", "--request"):
        i += 2
        continue
    if arg in ("--fail-with-body", "--silent", "--show-error"):
        i += 1
        continue
    if arg.startswith("https://"):
        url = arg
        i += 1
        continue
    raise SystemExit(f"unsupported curl arg: {arg}")

if data_path is None or url is None:
    raise SystemExit("missing upload inputs")

name = parse_qs(urlparse(url).query)["name"][0]
if os.environ.get("FAKE_CURL_FAIL_NAME") == name:
    raise SystemExit(22)

release = state.get("release")
if release is None or not release["draft"]:
    raise SystemExit("upload requires current draft")

digest = "sha256:" + hashlib.sha256(data_path.read_bytes()).hexdigest()
asset = {"name": name, "state": "uploaded", "digest": digest}
release["assets"].append(asset)
state_path.write_text(json.dumps(state))
print(json.dumps(asset))
'''


def write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def prepare_release(directory: Path) -> None:
    directory.mkdir()
    apk = directory / "Kenato-0.0.2.apk"
    aab = directory / "Kenato-0.0.2.aab"
    apk.write_bytes(b"deterministic apk fixture\n")
    aab.write_bytes(b"deterministic aab fixture\n")
    checksum = directory / "Kenato-0.0.2.sha256"
    checksum.write_text(
        f"{hashlib.sha256(apk.read_bytes()).hexdigest()}  {apk.name}\n"
        f"{hashlib.sha256(aab.read_bytes()).hexdigest()}  {aab.name}\n",
        encoding="utf-8",
    )


def run_case(
    *,
    initial_tag_sha: str | None = None,
    fail_asset: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict]:
    with tempfile.TemporaryDirectory(prefix="kenato-release-publisher-") as tmp:
        root = Path(tmp)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        write_executable(fake_bin / "gh", FAKE_GH)
        write_executable(fake_bin / "curl", FAKE_CURL)

        release_dir = root / "release"
        prepare_release(release_dir)

        state_path = root / "state.json"
        state = {
            "release": None,
            "deleted": False,
            "tag_exists": initial_tag_sha is not None,
            "tag_sha": initial_tag_sha or "",
            "tag_type": "commit",
        }
        state_path.write_text(json.dumps(state), encoding="utf-8")

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                "GITHUB_REPOSITORY": REPO,
                "GITHUB_SHA": SOURCE_SHA,
                "RELEASE_TAG": TAG,
                "RELEASE_DIR": str(release_dir),
                "GH_TOKEN": "test-token",
                "FAKE_RELEASE_STATE": str(state_path),
            }
        )
        if fail_asset is not None:
            env["FAKE_CURL_FAIL_NAME"] = fail_asset

        completed = subprocess.run(
            ["bash", str(PUBLISHER)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        final_state = json.loads(state_path.read_text(encoding="utf-8"))
        return completed, final_state


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_happy_path_without_preexisting_tag() -> None:
    completed, state = run_case()
    require(completed.returncode == 0, completed.stderr + completed.stdout)
    release = state["release"]
    require(release is not None and release["draft"] is False, "release was not published")
    require(len(release["assets"]) == 3, "expected exactly three assets")
    require(state["tag_exists"], "publication did not establish tag")
    require(state["tag_sha"] == SOURCE_SHA, "published tag points to wrong SHA")
    require(not state["deleted"], "successful release was unexpectedly deleted")


def test_failed_upload_cleans_only_current_draft() -> None:
    completed, state = run_case(fail_asset="Kenato-0.0.2.aab")
    require(completed.returncode != 0, "forced upload failure unexpectedly succeeded")
    require(state["release"] is None, "failed attempt left an unpublished draft")
    require(state["deleted"], "cleanup did not delete the failed attempt draft")


def test_wrong_preexisting_tag_fails_before_mutation() -> None:
    completed, state = run_case(initial_tag_sha="0" * 40)
    require(completed.returncode != 0, "wrong existing tag unexpectedly accepted")
    require(state["release"] is None, "release mutated despite wrong immutable tag")
    require(not state["deleted"], "nothing should need cleanup before release creation")


if __name__ == "__main__":
    test_happy_path_without_preexisting_tag()
    test_failed_upload_cleans_only_current_draft()
    test_wrong_preexisting_tag_fails_before_mutation()
    print("Android release publisher regression tests: OK")
