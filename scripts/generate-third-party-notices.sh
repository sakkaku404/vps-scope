#!/usr/bin/env bash
set -euo pipefail

umask 022
output="${1:-}"
[[ -n "$output" ]] || { echo "usage: $0 OUTPUT" >&2; exit 2; }
[[ ! -e "$output" ]] || { echo "refusing to overwrite $output" >&2; exit 1; }
parent="$(dirname -- "$output")"
[[ -d "$parent" ]] || { echo "output directory does not exist: $parent" >&2; exit 1; }

for command_name in basename cat chmod dirname go mktemp mv rm sed sort wc; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "required command not found: $command_name" >&2
    exit 1
  }
done

root_module="$(go list -m -f '{{.Path}}')"
modules="$(
  for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
      go list -deps -f '{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' ./cmd/vps-scope
  done | sed '/^$/d' | sort -u
)"
[[ -n "$modules" ]] || { echo "no dependency modules found" >&2; exit 1; }

temp="$(mktemp "$parent/.third-party-notices.XXXXXX")"
trap 'rm -f -- "$temp"' EXIT INT TERM HUP

cat >"$temp" <<'EOF'
VPS Scope third-party notices

This file contains the license notices shipped with the dependency modules
linked into the VPS Scope Linux amd64 or arm64 release binaries. The module
list is the union derived from `go list -deps ./cmd/vps-scope` for both targets.
EOF

count=0
while IFS='|' read -r module version directory; do
  [[ -n "$module" && "$module" != "$root_module" ]] || continue
  [[ -n "$version" && -d "$directory" ]] || {
    echo "incomplete module metadata for $module" >&2
    exit 1
  }
  license=""
  for candidate in LICENSE LICENSE.txt LICENSE.md COPYING; do
    if [[ -f "$directory/$candidate" && ! -L "$directory/$candidate" ]]; then
      license="$directory/$candidate"
      break
    fi
  done
  [[ -n "$license" ]] || { echo "no regular license file found for $module $version" >&2; exit 1; }
  size="$(wc -c <"$license")"
  (( size > 0 && size <= 262144 )) || {
    echo "license file size is outside the safety bound for $module: $size" >&2
    exit 1
  }
  {
    printf '\n================================================================================\n'
    printf 'Module: %s\nVersion: %s\nLicense file: %s\n' "$module" "$version" "$(basename -- "$license")"
    printf '================================================================================\n\n'
    cat -- "$license"
    printf '\n'
  } >>"$temp"
  count=$((count + 1))
done <<<"$modules"

(( count > 0 )) || { echo "no third-party notices were generated" >&2; exit 1; }
chmod 0644 "$temp"
mv -- "$temp" "$output"
trap - EXIT INT TERM HUP
printf 'generated %s with %d dependency license notices\n' "$output" "$count"
