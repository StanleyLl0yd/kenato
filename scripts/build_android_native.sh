#!/usr/bin/env bash
set -euo pipefail

readonly RUST_TOOLCHAIN="1.85.0"
readonly CARGO_NDK_VERSION="4.1.2"
readonly ANDROID_NDK_VERSION="28.2.13676358"
readonly ANDROID_API_LEVEL="26"
readonly LIBRARY_NAME="libkenato_session_jni.so"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate_dir="$repo_root/native/session-jni"
output_dir="$repo_root/android/app/build/generated/m3JniLibs"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
  if [[ -z "$sdk_root" ]]; then
    echo "ANDROID_NDK_HOME or ANDROID_SDK_ROOT/ANDROID_HOME must be set." >&2
    exit 1
  fi
  export ANDROID_NDK_HOME="$sdk_root/ndk/$ANDROID_NDK_VERSION"
fi

if [[ ! -f "$ANDROID_NDK_HOME/source.properties" ]]; then
  echo "Pinned Android NDK $ANDROID_NDK_VERSION is unavailable at $ANDROID_NDK_HOME." >&2
  exit 1
fi

actual_ndk_revision="$(sed -n 's/^Pkg.Revision[[:space:]]*=[[:space:]]*//p' "$ANDROID_NDK_HOME/source.properties" | head -1)"
if [[ "$actual_ndk_revision" != "$ANDROID_NDK_VERSION" ]]; then
  echo "Expected Android NDK $ANDROID_NDK_VERSION, found '$actual_ndk_revision'." >&2
  exit 1
fi

if ! rustc "+$RUST_TOOLCHAIN" --version | grep -Fq "rustc 1.85.0"; then
  echo "Rust $RUST_TOOLCHAIN is required for the M3 JNI library." >&2
  exit 1
fi

cargo_ndk_version="$(cargo ndk --version 2>/dev/null || true)"
if [[ "$cargo_ndk_version" != "cargo-ndk $CARGO_NDK_VERSION" ]]; then
  echo "cargo-ndk $CARGO_NDK_VERSION is required; found '${cargo_ndk_version:-missing}'." >&2
  exit 1
fi

for target in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; do
  rustup target list --toolchain "$RUST_TOOLCHAIN" --installed | grep -Fxq "$target" || {
    echo "Rust target $target is not installed for $RUST_TOOLCHAIN." >&2
    exit 1
  }
done

rm -rf "$output_dir"
mkdir -p "$output_dir"

(
  cd "$crate_dir"
  cargo "+$RUST_TOOLCHAIN" ndk \
    --platform "$ANDROID_API_LEVEL" \
    -t armeabi-v7a \
    -t arm64-v8a \
    -t x86_64 \
    -o "$output_dir" \
    build --release --locked
)

expected=(
  "armeabi-v7a/$LIBRARY_NAME"
  "arm64-v8a/$LIBRARY_NAME"
  "x86_64/$LIBRARY_NAME"
)

for relative in "${expected[@]}"; do
  file="$output_dir/$relative"
  if [[ ! -s "$file" ]]; then
    echo "Expected native library is missing or empty: $relative" >&2
    exit 1
  fi
done

mapfile -t actual < <(
  find "$output_dir" -type f -name '*.so' -printf '%P\n' | LC_ALL=C sort
)
mapfile -t expected_sorted < <(printf '%s\n' "${expected[@]}" | LC_ALL=C sort)

if [[ "${actual[*]}" != "${expected_sorted[*]}" ]]; then
  echo "Unexpected native library set." >&2
  printf 'Expected:\n%s\n' "${expected_sorted[*]}" >&2
  printf 'Actual:\n%s\n' "${actual[*]}" >&2
  exit 1
fi

printf 'M3 Android JNI libraries built with NDK %s / cargo-ndk %s / Rust %s.\n' \
  "$ANDROID_NDK_VERSION" "$CARGO_NDK_VERSION" "$RUST_TOOLCHAIN"
