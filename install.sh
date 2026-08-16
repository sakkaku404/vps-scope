#!/usr/bin/env bash
set -Eeuo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

REPO="sakkaku404/vps-scope"
VERSION="${VPS_SCOPE_VERSION:-latest}"
INSTALL_DIR="${VPS_SCOPE_INSTALL_DIR:-/usr/local/bin}"
ALLOW_UNSIGNED="${VPS_SCOPE_ALLOW_UNSIGNED:-0}"

usage() {
  cat <<'EOF'
Install VPS Scope from GitHub Release artifacts. Publisher signature
verification is required by default. If cosign is unavailable, an interactive
terminal must explicitly approve checksum-only mode; automation can set
VPS_SCOPE_ALLOW_UNSIGNED=1 after reviewing the trust trade-off.

Usage: install.sh [--version v1.0.0] [--install-dir /usr/local/bin] [--allow-unsigned]
EOF
}

while (($#)); do
  case "$1" in
    --version) VERSION="${2:?missing value for --version}"; shift 2 ;;
    --install-dir) INSTALL_DIR="${2:?missing value for --install-dir}"; shift 2 ;;
    --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if ((EUID != 0)); then
  echo "This installer needs root privileges. Run it with sudo." >&2
  exit 1
fi
if [[ "$ALLOW_UNSIGNED" != "0" && "$ALLOW_UNSIGNED" != "1" ]]; then
  echo "VPS_SCOPE_ALLOW_UNSIGNED must be 0 or 1." >&2
  exit 2
fi

if [[ "$VERSION" != "latest" && ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must be latest or a tag such as v0.11.0." >&2
  exit 2
fi
if [[ "$INSTALL_DIR" != /* || "$INSTALL_DIR" == *$'\n'* ]]; then
  echo "Install directory must be an absolute path." >&2
  exit 2
fi

for command_name in curl sha256sum install mktemp mv uname awk; do
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
  if [[ "$ALLOW_UNSIGNED" != "1" ]]; then
    echo "Publisher signature was not verified because cosign is not installed." >&2
    echo "SHA-256 from the same Release detects corruption but does not authenticate the publisher." >&2
    if { exec 3<>/dev/tty; } 2>/dev/null; then
      printf 'Type continue to accept checksum-only installation, or press Enter to stop: ' >&3
      IFS= read -r approval <&3 || true
      exec 3>&-
      if [[ "$approval" != "continue" ]]; then
        echo "Installation stopped without publisher verification." >&2
        exit 1
      fi
    else
      echo "Non-interactive installation stopped. Install cosign, or explicitly set VPS_SCOPE_ALLOW_UNSIGNED=1." >&2
      exit 1
    fi
  fi
  echo "WARNING: continuing with checksum integrity only; publisher signature was not verified." >&2
fi

install -d -m 0755 "$INSTALL_DIR"
install_temp="$(mktemp "$INSTALL_DIR/.vps-scope.XXXXXX")"
trap 'rm -f "$install_temp"; rm -rf "$temp_dir"' EXIT
install -m 0755 "$asset" "$install_temp"
mv -f -- "$install_temp" "$INSTALL_DIR/vps-scope"
echo "Installed: ${INSTALL_DIR}/vps-scope"
"$INSTALL_DIR/vps-scope" version
