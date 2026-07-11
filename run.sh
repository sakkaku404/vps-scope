#!/usr/bin/env bash
set -Eeuo pipefail

REPO="sakkaku404/vps-scope"
VERSION="${VPS_SCOPE_VERSION:-latest}"

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
chmod 0755 "$asset"

if (($# == 0)); then
  set -- audit --lang zh-CN --profile auto
fi
"./$asset" "$@"
