#!/usr/bin/env python3
"""Offline, host-free fail-safe policy for the operator-only OCI updater."""
from pathlib import Path
import subprocess

path = Path("scripts/rollout_existing_oci_arm64.sh")
text = path.read_text(encoding="utf-8")
subprocess.run(["bash", "-n", str(path)], check=True)
help_result = subprocess.run(["bash", str(path), "--help"], text=True, capture_output=True)
assert help_result.returncode == 0, help_result.stderr
refusal = subprocess.run(["bash", str(path)], text=True, capture_output=True)
assert refusal.returncode == 2, (refusal.stdout, refusal.stderr)

required = [
    'if [[ $# -ne 3 || "$1" != "--apply"',
    'if (( EUID != 0 ))',
    'source_sha=$expected_source',
    "vcs.modified=false",
    "go1.27.2",
    "SHA256SUMS",
    "readelf -h",
    "local_health()",
    "127.0.0.1:8080/healthz",
    'systemctl stop "$service"',
    'systemctl start "$service"',
    'trap rollback EXIT',
    'BACKUP_RETAINED',
    '/proc/$pid/exe',
    'PENDING: independently verify public HTTPS, authenticated WSS',
]
for marker in required:
    assert marker in text, f"Missing operator fail-safe marker: {marker}"
for forbidden in ("ssh ", "scp ", "curl -k", "--insecure", "systemctl enable", "ufw ", "iptables "):
    assert forbidden not in text, f"Rollout must not mutate remote/perimeter scope: {forbidden}"
print("Existing-OCI rollout static policy: PASS (not host acceptance)")
