#!/usr/bin/env bash
set -Eeuo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

REPO="sakkaku404/vps-scope"
VERSION="${VPS_SCOPE_VERSION:-latest}"
INSTALL_DIR="${VPS_SCOPE_INSTALL_DIR:-/usr/local/bin}"

usage() {
  cat <<'EOF'
Install VPS Scope from GitHub Release artifacts verified against SHA-256 checksums.
If cosign is installed, the release asset is also verified against the GitHub
Actions keyless signature. Set VPS_SCOPE_REQUIRE_SIGNATURE=1 to require it.

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

if [[ "$VERSION" != "latest" && ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must be latest or a tag such as v0.11.0." >&2
  exit 2
fi
if [[ "$INSTALL_DIR" != /* || "$INSTALL_DIR" == *$'\n'* ]]; then
  echo "Install directory must be an absolute path." >&2
  exit 2
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

if command -v cosign >/dev/null 2>&1; then
  curl "${curl_args[@]}" -o "${asset}.sigstore.json" "${base_url}/${asset}.sigstore.json"
  cosign verify-blob --bundle "${asset}.sigstore.json" \
    --certificate-identity-regexp '^https://github\.com/sakkaku404/vps-scope/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$asset"
  echo "Verified: GitHub Actions keyless signature"
elif [[ "${VPS_SCOPE_REQUIRE_SIGNATURE:-0}" == "1" ]]; then
  echo "cosign is required because VPS_SCOPE_REQUIRE_SIGNATURE=1." >&2
  exit 1
else
  echo "Note: SHA-256 verified. Install cosign or set VPS_SCOPE_REQUIRE_SIGNATURE=1 to require signature verification." >&2
fi

install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$asset" "$INSTALL_DIR/vps-scope"
echo "Installed: ${INSTALL_DIR}/vps-scope"
"$INSTALL_DIR/vps-scope" version
