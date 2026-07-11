#!/usr/bin/env bash
set -Eeuo pipefail

REPO="sakkaku404/vps-scope"
VERSION="${VPS_SCOPE_VERSION:-latest}"
INSTALL_DIR="${VPS_SCOPE_INSTALL_DIR:-/usr/local/bin}"

usage() {
  cat <<'EOF'
Install VPS Scope from its signed GitHub Release artifacts.

Usage: install.sh [--version v0.1.0] [--install-dir /usr/local/bin]
EOF
}

while (($#)); do
  case "$1" in
    --version) VERSION="${2:?missing value for --version}"; shift 2 ;;
    --install-dir) INSTALL_DIR="${2:?missing value for --install-dir}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if ((EUID != 0)); then
  echo "This installer needs root privileges. Run it with sudo." >&2
  exit 1
fi

for command_name in curl sha256sum install mktemp uname awk; do
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
echo "Downloading VPS Scope (${arch}, ${VERSION})..."
curl "${curl_args[@]}" -o "$asset" "${base_url}/${asset}"
curl "${curl_args[@]}" -o SHA256SUMS "${base_url}/SHA256SUMS"

expected="$(awk -v name="$asset" '$2 == name {print $1}' SHA256SUMS)"
if [[ -z "$expected" ]]; then
  echo "No checksum found for ${asset}. Installation stopped." >&2
  exit 1
fi
printf '%s  %s\n' "$expected" "$asset" | sha256sum -c -

install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$asset" "$INSTALL_DIR/vps-scope"
echo "Installed: ${INSTALL_DIR}/vps-scope"
"$INSTALL_DIR/vps-scope" version
