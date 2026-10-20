#!/usr/bin/env python3
"""Fail closed when locally compiled Kenato classes exceed Java 17 bytecode.

The JDK 25 toolchain is a build-time concern; Kenato Android sources stay
at JVM classfile major 61. Scans local intermediates/tmp, never vendor AAR.
This is not an Android Java API, supply-chain, or native-code audit.
"""
from __future__ import annotations

import argparse
import struct
import sys
import zipfile
from pathlib import Path

PREFIX = "com/sl/kenato/"
ENTRY = PREFIX + "MainActivity.class"


class TargetAuditError(ValueError):
    pass


def check_classfile(name: str, data: bytes, max_major: int) -> None:
    if len(data) < 8 or data[:4] != b"\xca\xfe\xba\xbe":
        raise TargetAuditError(f"{name}: invalid Java classfile")
    major = struct.unpack_from(">H", data, 6)[0]
    if major > max_major:
        raise TargetAuditError(f"{name}: classfile major {major} exceeds allowed {max_major}")


def audit(build_dir: Path, max_major: int = 61) -> tuple[int, int]:
    if not build_dir.is_dir():
        raise TargetAuditError("Android build directory not found")
    names: set[str] = set()
    count = 0
    for sub in ("intermediates", "tmp"):
        root = build_dir / sub
        if not root.exists():
            continue
        for path in root.rglob("*.class"):
            raw_name = path.as_posix()
            start = raw_name.find(PREFIX)
            if start < 0:
                continue
            name = raw_name[start:]
            check_classfile(name, path.read_bytes()[:8], max_major)
            names.add(name)
            count += 1
        for path in root.rglob("*.jar"):
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    if not (name.startswith(PREFIX) and name.endswith(".class")):
                        continue
                    member = archive.getinfo(name)
                    if member.file_size > 16 * 1024 * 1024:
                        raise TargetAuditError(f"{name}: oversized generated class")
                    check_classfile(name, archive.read(member)[:8], max_major)
                    names.add(name)
                    count += 1
    if ENTRY not in names:
        raise TargetAuditError("MainActivity.class missing from local Android build output")
    return count, len(names)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    parser.add_argument("--max-major", type=int, default=61)
    args = parser.parse_args()
    try:
        count, unique = audit(args.build_dir, args.max_major)
    except (TargetAuditError, OSError, zipfile.BadZipFile) as error:
        print(f"FAIL app Java target audit: {error}", file=sys.stderr)
        return 1
    print(f"PASS app Java target audit: {count} classfile entries, {unique} unique, max major {args.max_major}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
