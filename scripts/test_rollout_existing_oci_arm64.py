#!/usr/bin/env python3
"""Offline, host-free fail-safe policy for the operator-only OCI updater."""
from pathlib import Path
import subprocess
import re

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
    "pinned_source=04f8d78c3d730d512a9bca6462a4f4177db6ff58",
    "pinned_binary=f651a2519ea555d224f49897944561447dd6a8810353dd34c4e87f5ff28b97e9",
    "readelf -h",
    "local_health()",
    "127.0.0.1:8080/healthz",
    'systemctl stop "$service"',
    'systemctl start "$service"',
    'trap rollback EXIT',
    'BACKUP_RETAINED',
    '/proc/$pid/exe',
    'target_dir="$(dirname -- "$target")"',
    'mktemp "$target_dir/.kenato-install.XXXXXXXX"',
    'mktemp "$target_dir/.kenato-rollback.XXXXXXXX"',
    'mv -fT -- "$install_tmp" "$target"',
    'mv -fT -- "$rollback_tmp" "$target"',
    'sync -f "$install_tmp"',
    'sync -f "$target_dir"',
    'ss -H -ltnp | awk -v wanted="$service_pid"',
    'index($0, "pid=" wanted ",") == 0',
    'PENDING: independently verify public HTTPS, authenticated WSS',
]
for marker in required:
    assert marker in text, f"Missing operator fail-safe marker: {marker}"
for forbidden in ("ssh ", "scp ", "curl -k", "--insecure", "systemctl enable", "ufw ", "iptables "):
    assert forbidden not in text, f"Rollout must not mutate remote/perimeter scope: {forbidden}"
for unsafe in (
    'mv -f "$work/install.new" "$target"',
    'mv -f "$work/restore.new" "$target"',
):
    assert unsafe not in text, f"Cross-filesystem, non-atomic executable swap: {unsafe}"

# Execute the real awk listener policy against synthetic ss output, without
# contacting a host or starting a socket.
listener = re.search(
    r"""ss -H -ltnp \| awk -v wanted="\$service_pid" '(.*?)' \|\| return 1""",
    text,
    flags=re.DOTALL,
)
assert listener is not None, "Must retain isolated exact-PID socket guard"
awk = listener.group(1)
examples = (
    ('LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("kenato-server",pid=1234,fd=8))\n', True),
    ('LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("other-service",pid=5678,fd=8))\n', False),
    ('LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("kenato-server",pid=1234,fd=8))\n', False),
    ('LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("kenato-server",pid=1234,fd=8))\n'
     'LISTEN 0 4096 [::]:8080 [::]:* users:(("kenato-server",pid=1234,fd=10))\n', False),
    ('LISTEN 0 4096 127.0.0.1:8081 0.0.0.0:* users:(("kenato-server",pid=1234,fd=8))\n', False),
)
for ss_output, should_accept in examples:
    trial = subprocess.run(
        ["awk", "-v", "wanted=1234", awk],
        input=ss_output,
        text=True,
        capture_output=True,
        check=False,
    )
    assert (trial.returncode == 0) == should_accept, (
        "Incorrect exact-PID / loopback listener acceptance", ss_output
    )


operator = Path("scripts/Deploy-KenatoGoArm64.ps1").read_text(encoding="utf-8")
for token in (
    "sudo -n bash -s -- --apply",
    "$scriptText | & ssh",
    "$expectedZipSha",
    "$expectedElfSha",
):
    assert token in operator, f"Operator wrapper missing security marker: {token}"
for unsafe in (
    "ssh -tt",
    "scp -- $localHelper",
    "sudo bash $remotePath/rollout_existing_oci_arm64.sh",
):
    assert unsafe not in operator, f"Mutable unprivileged root script: {unsafe}"

print("Existing-OCI rollout static policy: PASS (not host acceptance)")
