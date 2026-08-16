#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
release="$work/release"
caller="$work/caller"
mkdir -p "$release" "$caller"

case "$(uname -m)" in
  x86_64|amd64) asset="vps-scope_linux_amd64" ;;
  aarch64|arm64) asset="vps-scope_linux_arm64" ;;
  *) echo "runner integration test does not support $(uname -m)" >&2; exit 1 ;;
esac

cat >"$release/$asset" <<'MOCK'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$PWD" >"$VPS_SCOPE_TEST_RECORD"
printf '%s\n' "$@" >>"$VPS_SCOPE_TEST_RECORD"
output=""
while (($#)); do
  if [[ "$1" == "--output" && $# -ge 2 ]]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
if [[ -n "$output" ]]; then
  printf 'mock report\n' >"$output"
fi
MOCK
chmod 0755 "$release/$asset"
digest="$(sha256sum "$release/$asset" | awk '{print $1}')"
printf '%s  %s\n' "$digest" "$asset" >"$release/SHA256SUMS"

record="$work/record.txt"
(
  cd "$caller"
  VPS_SCOPE_TEST_MODE=1 \
  VPS_SCOPE_TEST_RELEASE_DIR="$release" \
  VPS_SCOPE_TEST_RECORD="$record" \
    bash "$repo_root/run.sh" --lang en --format text --output relative-report.txt
)

mapfile -t recorded <"$record"
[[ "${recorded[0]}" == "$caller" ]] || {
  echo "runner changed caller working directory: ${recorded[0]}" >&2
  exit 1
}
[[ "${recorded[1]}" == "audit" ]] || {
  echo "leading flags were not converted to the audit command" >&2
  exit 1
}
[[ -f "$caller/relative-report.txt" ]] || {
  echo "relative output did not survive runner cleanup" >&2
  exit 1
}

if VPS_SCOPE_TEST_MODE=1 \
  VPS_SCOPE_TEST_RELEASE_DIR="$release" \
  VPS_SCOPE_TEST_RECORD="$record" \
    bash "$repo_root/run.sh" </dev/null >"$work/no-tty.out" 2>"$work/no-tty.err"; then
  echo "runner unexpectedly started interactive mode without a controlling terminal" >&2
  exit 1
fi
grep -Fq 'Interactive input is unavailable' "$work/no-tty.err"

printf 'runner integration: PASS\n'
