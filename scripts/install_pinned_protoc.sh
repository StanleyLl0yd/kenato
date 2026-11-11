#!/usr/bin/env bash
# Install the official, digest-pinned protocol compiler without relying on APT mirrors.
set -Eeuo pipefail

: "${RUNNER_TEMP:?GitHub runner temporary directory is required}"
: "${GITHUB_PATH:?GitHub Actions path file is required}"

version=33.1
expected_sha256=f3340e28a83d1c637d8bafdeed92b9f7db6a384c26bca880a6e5217b40a4328b
url="https://github.com/protocolbuffers/protobuf/releases/download/v${version}/protoc-${version}-linux-x86_64.zip"
archive="$(mktemp "$RUNNER_TEMP/kenato-protoc.XXXXXXXX.zip")"
scratch="$(mktemp -d "$RUNNER_TEMP/kenato-protoc.XXXXXXXX")"
trap 'rm -f -- "$archive"; rm -rf -- "$scratch"' EXIT

curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
  --connect-timeout 15 --max-time 120 --proto '=https' --proto-redir '=https' \
  --output "$archive" "$url"
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check --status
unzip -p "$archive" bin/protoc > "$scratch/protoc"
chmod 0700 "$scratch/protoc"
test "$("$scratch/protoc" --version)" = "libprotoc $version"

destination="$RUNNER_TEMP/kenato-protoc-$version"
mkdir -p "$destination"
install -m 0755 "$scratch/protoc" "$destination/protoc"
printf '%s\n' "$destination" >> "$GITHUB_PATH"
