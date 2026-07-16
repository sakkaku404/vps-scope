#!/usr/bin/env bash
set -euo pipefail

# The ratchet is intentionally a Linux gate.  The audited product only runs on
# Linux and a small set of filesystem tests needs unprivileged symlink support,
# which standard Windows development environments do not provide.  Refuse with
# an actionable message rather than presenting the resulting partial coverage
# as a regression in the Linux CI baseline.
if [[ "$(go env GOOS)" != "linux" ]]; then
  echo "coverage ratchet requires Linux; run it in WSL/Linux or use GitHub CI" >&2
  exit 2
fi

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
check_package app 56
check_package audit 54
check_package redact 86
check_package report 82
