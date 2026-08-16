#!/usr/bin/env bash
set -Eeuo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

REPO="sakkaku404/vps-scope"
VERSION="${VPS_SCOPE_VERSION:-latest}"
ORIGINAL_DIR="$PWD"
TEST_RELEASE_DIR="${VPS_SCOPE_TEST_RELEASE_DIR:-}"

if [[ -n "$TEST_RELEASE_DIR" && "${VPS_SCOPE_TEST_MODE:-0}" != "1" ]]; then
  echo "VPS_SCOPE_TEST_RELEASE_DIR is available only with VPS_SCOPE_TEST_MODE=1." >&2
  exit 2
fi

if [[ "$VERSION" != "latest" && ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must be latest or a tag such as v0.11.0." >&2
  exit 2
fi

required_commands=(sha256sum mktemp uname awk)
if [[ -z "$TEST_RELEASE_DIR" ]]; then
  required_commands+=(curl)
else
  required_commands+=(cp)
fi
for command_name in "${required_commands[@]}"; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Required command not found: $command_name" >&2
    exit 1
  }
done

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

asset="vps-scope_linux_${arch}"
if [[ "$VERSION" == "latest" ]]; then
  base_url="https://github.com/${REPO}/releases/latest/download"
else
  base_url="https://github.com/${REPO}/releases/download/${VERSION}"
fi

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT
cd "$temp_dir"

curl_args=(--proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --silent --show-error --connect-timeout 10 --max-time 120 --retry 3 --retry-all-errors)
if [[ -n "$TEST_RELEASE_DIR" ]]; then
  [[ "$TEST_RELEASE_DIR" == /* ]] || {
    echo "VPS_SCOPE_TEST_RELEASE_DIR must be an absolute path." >&2
    exit 2
  }
  cp -- "$TEST_RELEASE_DIR/$asset" "$asset"
  cp -- "$TEST_RELEASE_DIR/SHA256SUMS" SHA256SUMS
else
  curl "${curl_args[@]}" -o "$asset" "${base_url}/${asset}"
  curl "${curl_args[@]}" -o SHA256SUMS "${base_url}/SHA256SUMS"
fi

expected="$(awk -v name="$asset" '$2 == name {print $1}' SHA256SUMS)"
if [[ -z "$expected" ]]; then
  echo "No checksum found for ${asset}. Run stopped." >&2
  exit 1
fi
printf '%s  %s\n' "$expected" "$asset" | sha256sum -c -

if [[ -z "$TEST_RELEASE_DIR" ]] && command -v cosign >/dev/null 2>&1; then
  curl "${curl_args[@]}" -o "${asset}.sigstore.json" "${base_url}/${asset}.sigstore.json"
  identity_args=(--certificate-identity-regexp '^https://github\.com/sakkaku404/vps-scope/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$')
  if [[ "$VERSION" != "latest" ]]; then
    identity_args=(--certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}")
  fi
  cosign verify-blob --bundle "${asset}.sigstore.json" \
    "${identity_args[@]}" \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$asset"
  echo "Verified: GitHub Actions keyless signature"
else
  if [[ "${VPS_SCOPE_REQUIRE_SIGNATURE:-0}" == "1" ]]; then
    echo "cosign is required because VPS_SCOPE_REQUIRE_SIGNATURE=1." >&2
    exit 1
  fi
  echo "WARNING: cosign is not installed; SHA-256 passed, but the publisher signature was not verified." >&2
fi
chmod 0755 "$asset"
asset_path="$temp_dir/$asset"
cd "$ORIGINAL_DIR"

# A leading flag is shorthand for the audit command. This makes
# `bash -s -- --lang en --profile proxy` behave as users expect.
if (($# > 0)) && [[ "$1" == -* ]]; then
  set -- audit "$@"
fi

# Explicit commands are non-interactive and must keep ordinary stdin semantics.
# With no arguments, the runner was itself read from stdin, so reconnect only
# after proving that /dev/tty can actually be opened.
if (($# > 0)); then
  "$asset_path" "$@"
elif { exec 3<>/dev/tty; } 2>/dev/null; then
  "$asset_path" <&3
  exec 3>&-
else
  echo "Interactive input is unavailable. Run this command in a terminal, or pass explicit audit flags." >&2
  exit 2
fi
