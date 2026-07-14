#!/usr/bin/env bash
set -euo pipefail

test -z "$(gofmt -l .)"
go mod verify
go vet ./...
go test -count=1 ./...
"$(dirname "$0")/check-coverage.sh"
bash -n install.sh run.sh scripts/check-coverage.sh scripts/regression.sh

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$tmp/vps-scope-linux-amd64" ./cmd/vps-scope
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$tmp/vps-scope-linux-arm64" ./cmd/vps-scope
"$tmp/vps-scope-linux-amd64" version
