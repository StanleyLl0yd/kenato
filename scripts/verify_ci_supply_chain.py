#!/usr/bin/env python3
import re
from pathlib import Path

ROOTS = (Path(".github/workflows"), Path(".github/actions"))
ACTION_REF = re.compile(r"^\s*uses:\s*([^\s#]+)")
IMAGE = re.compile(r"^\s*image:\s*([^\s#]+)")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
TOP_LEVEL_PERMISSIONS = re.compile(r"(?m)^permissions:\s*(.*?)\s*$")
UNSAFE_DOWNLOAD_EXEC = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b")

errors: list[str] = []

for root in ROOTS:
    if not root.exists():
        continue
    for path in sorted(root.rglob("*")):
        if path.suffix not in {".yml", ".yaml"}:
            continue

        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()

        if "pull_request_target:" in text:
            errors.append(f"{path}: pull_request_target is forbidden")
        if "secrets: inherit" in text:
            errors.append(f"{path}: inherited reusable-workflow secrets are forbidden")
        if "persist-credentials: true" in text:
            errors.append(f"{path}: checkout credentials must not persist")
        if UNSAFE_DOWNLOAD_EXEC.search(text):
            errors.append(f"{path}: downloaded content must not be piped directly to a shell")

        if path.parent == Path(".github/workflows"):
            permission_matches = TOP_LEVEL_PERMISSIONS.findall(text)
            if permission_matches != ["{}"]:
                errors.append(
                    f"{path}: exactly one explicitly empty top-level workflow permissions mapping is required"
                )

        for number, line in enumerate(lines, start=1):
            action = ACTION_REF.match(line)
            if action:
                target = action.group(1)
                if target.startswith("./"):
                    continue
                if target.startswith("docker://"):
                    if not DIGEST.search(target):
                        errors.append(
                            f"{path}:{number}: docker action must be pinned by sha256 digest"
                        )
                    continue
                if "@" not in target:
                    errors.append(f"{path}:{number}: action is not pinned")
                    continue

                name, ref = target.rsplit("@", 1)
                if not FULL_SHA.fullmatch(ref):
                    errors.append(
                        f"{path}:{number}: {name} must use a full 40-character commit SHA"
                    )

                if name == "actions/checkout":
                    uses_indent = len(line) - len(line.lstrip())
                    step_indent = max(0, uses_indent - 2)
                    block = []
                    for following in lines[number:]:
                        stripped = following.lstrip()
                        indent = len(following) - len(stripped)
                        if stripped.startswith("- ") and indent <= step_indent:
                            break
                        block.append(following)
                    if not any(
                        re.search(r"\bpersist-credentials:\s*false\b", item)
                        for item in block
                    ):
                        errors.append(
                            f"{path}:{number}: actions/checkout must set persist-credentials: false"
                        )

            image = IMAGE.match(line)
            if image:
                target = image.group(1)
                if target.startswith("${{"):
                    errors.append(f"{path}:{number}: dynamic container images are forbidden")
                elif not DIGEST.search(target):
                    errors.append(
                        f"{path}:{number}: container image must be pinned by sha256 digest"
                    )

if errors:
    raise SystemExit("\n".join(errors))

print("GitHub Actions supply-chain policy: OK")
