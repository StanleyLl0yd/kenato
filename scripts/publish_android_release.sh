#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]

version="${RELEASE_TAG#v}"
release_dir="${RELEASE_DIR:-release}"
apk_path="$release_dir/Kenato-$version.apk"
aab_path="$release_dir/Kenato-$version.aab"
checksum_path="$release_dir/Kenato-$version.sha256"

for path in "$apk_path" "$aab_path" "$checksum_path"; do
  test -s "$path"
done

(
  cd "$release_dir"
  sha256sum --check "Kenato-$version.sha256"
)

release_id=""

gh_api_optional() {
  local endpoint="$1"
  local error_file output

  error_file="$(mktemp)"
  if output="$(gh api "$endpoint" 2>"$error_file")"; then
    rm -f "$error_file"
    printf '%s' "$output"
    return 0
  fi

  if grep -Fq "(HTTP 404)" "$error_file"; then
    rm -f "$error_file"
    return 1
  fi

  cat "$error_file" >&2
  rm -f "$error_file"
  return 2
}

cleanup_unpublished_draft() {
  local draft_state

  [[ -n "$release_id" ]] || return 0
  draft_state="$(gh api "repos/$GITHUB_REPOSITORY/releases/$release_id" --jq '.draft' 2>/dev/null || true)"
  if [[ "$draft_state" == "true" ]]; then
    echo "Cleaning unpublished release draft $release_id after failed publication attempt." >&2
    gh api --method DELETE "repos/$GITHUB_REPOSITORY/releases/$release_id" >/dev/null || {
      echo "WARNING: failed to delete unpublished release draft $release_id." >&2
      return 0
    }
  fi
}

trap cleanup_unpublished_draft EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

require_exact_main_and_tag() {
  local current_main_sha tag_json tag_sha tag_type resolved_tag_sha

  current_main_sha="$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq '.object.sha')"
  test "$current_main_sha" = "$GITHUB_SHA"

  if tag_json="$(gh_api_optional "repos/$GITHUB_REPOSITORY/git/ref/tags/$RELEASE_TAG")"; then
    tag_sha="$(jq -r '.object.sha' <<< "$tag_json")"
    tag_type="$(jq -r '.object.type' <<< "$tag_json")"
    test "$tag_type" = "commit"
    resolved_tag_sha="$(gh api "repos/$GITHUB_REPOSITORY/commits/$RELEASE_TAG" --jq '.sha')"
    test "$tag_sha" = "$GITHUB_SHA"
    test "$resolved_tag_sha" = "$GITHUB_SHA"
  else
    optional_status=$?
    (( optional_status == 1 )) || return "$optional_status"
  fi
}

verify_release_assets() {
  local release_json="$1"
  local path asset_name expected_digest remote_count remote_digest remote_state

  for path in "$apk_path" "$aab_path" "$checksum_path"; do
    asset_name="$(basename "$path")"
    expected_digest="sha256:$(sha256sum "$path" | awk '{print $1}')"
    remote_count="$(jq --arg name "$asset_name" '[.assets[] | select(.name == $name)] | length' <<< "$release_json")"
    test "$remote_count" = "1"
    remote_digest="$(jq -r --arg name "$asset_name" '.assets[] | select(.name == $name) | .digest // ""' <<< "$release_json")"
    remote_state="$(jq -r --arg name "$asset_name" '.assets[] | select(.name == $name) | .state // ""' <<< "$release_json")"
    test "$remote_state" = "uploaded"
    test "$remote_digest" = "$expected_digest"
  done

  test "$(jq '.assets | length' <<< "$release_json")" = "3"
}

require_exact_main_and_tag

if published_probe="$(gh_api_optional "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG")"; then
  echo "Release $RELEASE_TAG became published before canonical publication started." >&2
  exit 1
else
  optional_status=$?
  (( optional_status == 1 )) || exit "$optional_status"
fi

tag_exists=false
if tag_probe="$(gh_api_optional "repos/$GITHUB_REPOSITORY/git/ref/tags/$RELEASE_TAG")"; then
  tag_exists=true
else
  optional_status=$?
  (( optional_status == 1 )) || exit "$optional_status"
fi

create_args=(
  --method POST
  "repos/$GITHUB_REPOSITORY/releases"
  -f "tag_name=$RELEASE_TAG"
  -f "target_commitish=$GITHUB_SHA"
  -f "name=Kenato $version"
  -F draft=true
  -F prerelease=false
  -F generate_release_notes=true
)

created="$(gh api "${create_args[@]}")"
release_id="$(jq -r '.id // empty' <<< "$created")"
upload_template="$(jq -r '.upload_url // empty' <<< "$created")"
test -n "$release_id"

expected_upload_base="https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets"
test "$upload_template" = "$expected_upload_base{?name,label}"
upload_base="${upload_template%%\{*}"
test "$upload_base" = "$expected_upload_base"

test "$(jq -r '.draft' <<< "$created")" = "true"
test "$(jq -r '.tag_name' <<< "$created")" = "$RELEASE_TAG"
test "$(jq '.assets | length' <<< "$created")" = "0"

if [[ "$tag_exists" == "false" ]]; then
  test "$(jq -r '.target_commitish' <<< "$created")" = "$GITHUB_SHA"
fi

echo "Created canonical release draft ID $release_id."

for path in "$apk_path" "$aab_path" "$checksum_path"; do
  asset_name="$(basename "$path")"
  expected_digest="sha256:$(sha256sum "$path" | awk '{print $1}')"
  upload_url="$upload_base?name=$asset_name"

  uploaded="$(curl \
    --fail-with-body \
    --silent \
    --show-error \
    --request POST \
    --header "Accept: application/vnd.github+json" \
    --header "Authorization: Bearer $GH_TOKEN" \
    --header "X-GitHub-Api-Version: 2026-03-10" \
    --header "Content-Type: application/octet-stream" \
    --data-binary "@$path" \
    "$upload_url")"

  test "$(jq -r '.name' <<< "$uploaded")" = "$asset_name"
  test "$(jq -r '.state' <<< "$uploaded")" = "uploaded"
  test "$(jq -r '.digest // ""' <<< "$uploaded")" = "$expected_digest"
done

draft_json="$(gh api "repos/$GITHUB_REPOSITORY/releases/$release_id")"
test "$(jq -r '.draft' <<< "$draft_json")" = "true"
test "$(jq -r '.tag_name' <<< "$draft_json")" = "$RELEASE_TAG"
verify_release_assets "$draft_json"

require_exact_main_and_tag

published="$(gh api \
  --method PATCH \
  "repos/$GITHUB_REPOSITORY/releases/$release_id" \
  -F draft=false \
  -f make_latest=true)"

test "$(jq -r '.draft' <<< "$published")" = "false"
test "$(jq -r '.tag_name' <<< "$published")" = "$RELEASE_TAG"
test -n "$(jq -r '.published_at // ""' <<< "$published")"
verify_release_assets "$published"

published_by_id="$(gh api "repos/$GITHUB_REPOSITORY/releases/$release_id")"
published_by_tag="$(gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG")"

test "$(jq -r '.id' <<< "$published_by_id")" = "$release_id"
test "$(jq -r '.id' <<< "$published_by_tag")" = "$release_id"
test "$(jq -r '.draft' <<< "$published_by_id")" = "false"
test "$(jq -r '.draft' <<< "$published_by_tag")" = "false"
verify_release_assets "$published_by_id"
verify_release_assets "$published_by_tag"

tag_json="$(gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$RELEASE_TAG")"
test "$(jq -r '.object.type' <<< "$tag_json")" = "commit"
test "$(jq -r '.object.sha' <<< "$tag_json")" = "$GITHUB_SHA"
test "$(gh api "repos/$GITHUB_REPOSITORY/commits/$RELEASE_TAG" --jq '.sha')" = "$GITHUB_SHA"

echo "Published $RELEASE_TAG from exact commit $GITHUB_SHA as release ID $release_id."
