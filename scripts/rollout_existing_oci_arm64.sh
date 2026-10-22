#!/usr/bin/env bash
# Explicit operator-only update of the existing Kenato OCI binary.
# No SSH, credentials, firewall, TLS, DB or new service changes.
set -Eeuo pipefail
umask 077

usage() {
  printf 'Usage: sudo bash %s --apply EXTRACTED_ARTIFACT_DIR EXACT_SOURCE_SHA\n' "$0"
  printf 'Requires reviewed artifact, authorized change window and independent external HTTPS/WSS checks.\n'
}

if [[ "${1:-}" == "--help" ]]; then usage; exit 0; fi
if [[ $# -ne 3 || "$1" != "--apply" || ! "$3" =~ ^[0-9a-f]{40}$ ]]; then
  usage >&2
  exit 2
fi
if (( EUID != 0 )); then
  echo 'ERROR: run as root on the authorized EXISTING OCI host.' >&2
  exit 2
fi

artifact_dir="$2"
expected_source="$3"
# Hard-pin the previously source-verified GitHub Actions artifact. A checksum
# carried inside the same untrusted archive is not an independent trust anchor.
pinned_source=04f8d78c3d730d512a9bca6462a4f4177db6ff58
pinned_binary=f651a2519ea555d224f49897944561447dd6a8810353dd34c4e87f5ff28b97e9
[[ "$expected_source" == "$pinned_source" ]] || {
  echo 'Unreviewed backend source revision' >&2; exit 1;
}
service=kenato-server
target=/usr/local/bin/kenato-server
backup_root=/var/backups/kenato
binary=kenato-server-linux-arm64

for cmd in systemctl sha256sum readelf install mktemp cp mv ss curl awk grep stat sync dirname rm; do
  command -v "$cmd" >/dev/null || { echo "Missing required command: $cmd" >&2; exit 1; }
done
[[ -d "$artifact_dir" && ! -L "$artifact_dir" ]] || { echo 'Invalid artifact directory' >&2; exit 1; }
for f in "$binary" SHA256SUMS GO_BUILD_INFO.txt PROVENANCE.txt; do
  [[ -f "$artifact_dir/$f" && ! -L "$artifact_dir/$f" ]] || {
    echo "Missing or linked artifact member: $f" >&2
    exit 1
  }
done

# The downloaded GitHub archive digest and provenance must also be checked
# independently by the operator, BEFORE unpacking and using this local script.
expected_line="$(cat "$artifact_dir/SHA256SUMS")"
[[ "$expected_line" =~ ^([0-9a-f]{64})[[:space:]]+kenato-server-linux-arm64$ ]] || {
  echo 'Noncanonical SHA256SUMS: refusing rollout' >&2; exit 1;
}
expected_binary="${BASH_REMATCH[1]}"
[[ "$expected_binary" == "$pinned_binary" ]] || {
  echo 'Unreviewed ARM64 binary digest' >&2; exit 1;
}
[[ "$(sha256sum "$artifact_dir/$binary" | awk '{print $1}')" == "$expected_binary" ]] || {
  echo 'Artifact binary SHA-256 mismatch' >&2; exit 1;
}
grep -Fxq "source_sha=$expected_source" "$artifact_dir/PROVENANCE.txt"
grep -Fxq 'source_ref=refs/heads/main' "$artifact_dir/PROVENANCE.txt"
grep -Fxq 'goos=linux' "$artifact_dir/PROVENANCE.txt"
grep -Fxq 'goarch=arm64' "$artifact_dir/PROVENANCE.txt"
grep -Fxq 'cgo_enabled=0' "$artifact_dir/PROVENANCE.txt"
grep -Fq 'go1.27.2' "$artifact_dir/GO_BUILD_INFO.txt"
grep -Fq "vcs.revision=$expected_source" "$artifact_dir/GO_BUILD_INFO.txt"
grep -Fq 'vcs.modified=false' "$artifact_dir/GO_BUILD_INFO.txt"
grep -Fq 'GOOS=linux' "$artifact_dir/GO_BUILD_INFO.txt"
grep -Fq 'GOARCH=arm64' "$artifact_dir/GO_BUILD_INFO.txt"
grep -Fq 'CGO_ENABLED=0' "$artifact_dir/GO_BUILD_INFO.txt"
readelf -h "$artifact_dir/$binary" | grep -Eq 'Machine:[[:space:]]*AArch64'

[[ -f "$target" && ! -L "$target" && -x "$target" ]] || {
  echo 'Existing target executable missing or unsafe: refusing first-time install' >&2; exit 1;
}
[[ "$(stat -c '%U:%G' "$target")" == 'root:root' ]] || {
  echo 'Existing binary ownership is not root:root' >&2; exit 1;
}

local_health() {
  systemctl is-active --quiet "$service" || return 1
  curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8080/healthz >/dev/null || return 1
  ss -H -ltn | awk '
    $4 ~ /:8080$/ { found++; if ($4 != "127.0.0.1:8080") bad=1 }
    END { if (found != 1 || bad) exit 1 }
  ' || return 1
}
local_health || { echo 'Existing host/service unhealthy before deployment; no changes made' >&2; exit 1; }

# Copy untrusted staging files into a root-owned private directory before changing
# the live executable, preventing a post-verification source-path race.
install -d -o root -g root -m 0700 "$backup_root"
work="$(mktemp -d "$backup_root/rollout.XXXXXXXX")"
install -o root -g root -m 0700 "$artifact_dir/$binary" "$work/candidate"
[[ "$(sha256sum "$work/candidate" | awk '{print $1}')" == "$expected_binary" ]] || {
  echo 'Private staged candidate checksum mismatch' >&2; exit 1;
}
cp --preserve=mode,ownership,timestamps "$target" "$work/previous"
sync -f "$work/previous"
[[ "$(sha256sum "$work/previous" | awk '{print $1}')" == "$(sha256sum "$target" | awk '{print $1}')" ]] || {
  echo 'Previous binary backup mismatch' >&2; exit 1;
}
previous_sha="$(sha256sum "$work/previous" | awk '{print $1}')"
if [[ "$previous_sha" == "$expected_binary" ]]; then
  echo 'Requested binary already installed; no restart performed.'
  exit 0
fi

# Stage in the TARGET directory, not under /var/backups: mv across
# filesystems degrades to copy+unlink and is not an atomic executable swap.
# A unique root-owned regular file also avoids predictable temp-path symlinks.
target_dir="$(dirname -- "$target")"
install_tmp="$(mktemp "$target_dir/.kenato-install.XXXXXXXX")"
rollback_tmp=""
cleanup_temps() {
  [[ -z "$install_tmp" ]] || rm -f -- "$install_tmp"
  [[ -z "$rollback_tmp" ]] || rm -f -- "$rollback_tmp"
}
install -o root -g root -m 0755 "$work/candidate" "$install_tmp"
[[ "$(sha256sum "$install_tmp" | awk '{print $1}')" == "$expected_binary" ]]
sync -f "$install_tmp"

armed=1
rollback() {
  status=$?
  trap - EXIT
  cleanup_temps
  if (( armed )); then
    echo 'ROLLBACK: restoring previous Kenato executable' >&2
    if ! systemctl stop "$service"; then
      echo 'WARNING: service stop during rollback failed; attempting recovery' >&2
    fi
    rollback_tmp="$(mktemp "$target_dir/.kenato-rollback.XXXXXXXX")"
    install -o root -g root -m 0755 "$work/previous" "$rollback_tmp"
    sync -f "$rollback_tmp"
    mv -fT -- "$rollback_tmp" "$target"
    rollback_tmp=""
    sync -f "$target_dir"
    if ! systemctl start "$service" || ! local_health; then
      echo 'CRITICAL: rollback health failed; operator intervention required' >&2
      exit 1
    fi
    echo 'ROLLBACK_OK: prior executable restored and local health passed' >&2
  fi
  exit "$status"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

systemctl stop "$service"
mv -fT -- "$install_tmp" "$target"
install_tmp=""
sync -f "$target_dir"
[[ "$(sha256sum "$target" | awk '{print $1}')" == "$expected_binary" ]]
systemctl start "$service"
local_health

# Verify the actually running process, not only the on-disk file.
pid="$(systemctl show --property=MainPID --value "$service")"
[[ "$pid" =~ ^[1-9][0-9]*$ ]]
[[ "$(sha256sum "/proc/$pid/exe" | awk '{print $1}')" == "$expected_binary" ]]
armed=0
trap - EXIT
cleanup_temps
echo "LOCAL_ROLLOUT_PASS source=$expected_source binary_sha256=$expected_binary"
echo "BACKUP_RETAINED $work/previous"
echo 'PENDING: independently verify public HTTPS, authenticated WSS and rollback readiness.'
