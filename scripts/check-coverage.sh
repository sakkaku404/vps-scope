#!/usr/bin/env bash
set -euo pipefail

check_package() {
  package="$1"
  threshold="$2"
  profile="$(mktemp)"
  trap 'rm -f "$profile"' RETURN
  go test -count=1 -coverprofile "$profile" "./internal/$package"
  actual="$(go tool cover -func "$profile" | awk '/^total:/ {gsub("%", "", $3); print $3}')"
  awk -v package="$package" -v actual="$actual" -v threshold="$threshold" 'BEGIN {
    printf "%s coverage: %.1f%% (minimum %.1f%%)\n", package, actual, threshold
    if (actual + 0 < threshold + 0) exit 1
  }'
  rm -f "$profile"
  trap - RETURN
}

# These floors are a ratchet, not a target. Raise them as collectors are split
# behind typed interfaces and gain deterministic fixtures.
check_package app 46
check_package audit 51
check_package redact 86
check_package report 82
