#!/usr/bin/env bash
set -Eeuo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

REPO="sakkaku404/vps-scope"
VERSION="${VPS_SCOPE_VERSION:-latest}"

if [[ "$VERSION" != "latest" && ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must be latest or a tag such as v0.11.0." >&2
  exit 2
fi

for command_name in curl sha256sum mktemp uname awk; do
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

curl_args=(--proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 3)
curl "${curl_args[@]}" -o "$asset" "${base_url}/${asset}"
curl "${curl_args[@]}" -o SHA256SUMS "${base_url}/SHA256SUMS"

expected="$(awk -v name="$asset" '$2 == name {print $1}' SHA256SUMS)"
if [[ -z "$expected" ]]; then
  echo "No checksum found for ${asset}. Run stopped." >&2
  exit 1
fi
printf '%s  %s\n' "$expected" "$asset" | sha256sum -c -

if command -v cosign >/dev/null 2>&1; then
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
elif [[ "${VPS_SCOPE_REQUIRE_SIGNATURE:-0}" == "1" ]]; then
  echo "cosign is required because VPS_SCOPE_REQUIRE_SIGNATURE=1." >&2
  exit 1
else
  echo "Note: SHA-256 verified. Install cosign or set VPS_SCOPE_REQUIRE_SIGNATURE=1 to require signature verification." >&2
fi
chmod 0755 "$asset"

"./$asset" "$@"
