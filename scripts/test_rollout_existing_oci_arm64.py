#!/usr/bin/env python3
"""Offline, host-free fail-safe policy for the operator-only OCI updater."""
from pathlib import Path
import subprocess
import re
import hashlib

path = Path("scripts/rollout_existing_oci_arm64.sh")
text = path.read_text(encoding="utf-8")
subprocess.run(["bash", "-n", str(path)], check=True)
help_result = subprocess.run(["bash", str(path), "--help"], text=True, capture_output=True)
assert help_result.returncode == 0, help_result.stderr
refusal = subprocess.run(["bash", str(path)], text=True, capture_output=True)
assert refusal.returncode == 2, (refusal.stdout, refusal.stderr)
# Retired artifact must fail before root privilege, file or systemd checks.
retired = subprocess.run(
    ["bash", str(path), "--apply", "/nonexistent/obsolete-kenato-artifact", "a" * 40],
    text=True, capture_output=True,
)
assert retired.returncode == 3, (retired.stdout, retired.stderr)
assert "GO-2026-6859" in retired.stderr

required = [
    'if [[ $# -ne 3 || "$1" != "--apply"',
    'if (( EUID != 0 ))',
    'source_sha=$expected_source',
    "vcs.modified=false",
    "go1.27.3",
    "SHA256SUMS",
    "pinned_source=aa3bcebe646bd84ce3be0dd4357840ca31acd71d",
    "pinned_binary=c3fda56f38ea3b1e7e8243bfc7a0e72ff819af32052e4a377a177e9b86d54107",
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
reviewed_digest = "1cb7f9f8f232ec975d8154ab06d5f115f3a0ca3e9fd4a0ebef2dcf614c41b6cc"
assert hashlib.sha256(path.read_bytes()).hexdigest() == reviewed_digest
assert "$sourceSha = 'aa3bcebe646bd84ce3be0dd4357840ca31acd71d'" in operator
assert "$expectedZipSha = '0feebe4644b8650569db9c3cb0fe24595ae16bd61915a14a39f70d2c51aecf0d'" in operator
assert "$expectedElfSha = 'c3fda56f38ea3b1e7e8243bfc7a0e72ff819af32052e4a377a177e9b86d54107'" in operator
assert "$expectedRootHelperSha = '1cb7f9f8f232ec975d8154ab06d5f115f3a0ca3e9fd4a0ebef2dcf614c41b6cc'" in operator
assert f"$expectedRootHelperSha = '{reviewed_digest}'" in operator
assert "if ($Apply) {" in operator and "GO-2026-6859" in operator
assert operator.index("if ($Apply) {") < operator.index("$zipSha = (Get-FileHash")
assert operator.index("$scriptHash -cne $expectedRootHelperSha") < operator.index(
    '& ssh $SshAlias "umask 077; mkdir -p'
), "Unreviewed shell helper must be rejected before any SSH host mutation"
assert hashlib.sha256(path.read_bytes() + b"\n# unreviewed change").hexdigest() != reviewed_digest

# The SSH host alias is a user-controlled CLI argument. It must not become
# an OpenSSH option by beginning with '-', including flags such as '-F'.
assert "[ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')]" in operator
assert not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", "-V")
assert not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", "-Fother")
assert re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", "kenato-prod") is not None

for token in (
    "sudo -n bash -s -- --apply",
    "$scriptText | & ssh",
    '$scriptText = (Get-Content -LiteralPath $localHelper -Raw -Encoding utf8) -replace "`r`n", "`n"',
    '$scriptText.Contains("`r")',
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

# Guard both the pre-stop executable baseline and the post-rollback process,
# not merely the on-disk file or the HTTP listener.
assert 'sha256sum "/proc/$existing_pid/exe"' in text
assert 'sha256sum "/proc/$rollback_pid/exe"' in text
assert '!= "$previous_sha"' in text
assert text.index('sha256sum "/proc/$existing_pid/exe"') < text.index('systemctl stop "$service"')
assert text.index('sha256sum "/proc/$rollback_pid/exe"') < text.index('ROLLBACK_OK:')
assert 'CRITICAL: rollback process executable digest mismatch' in text
