#!/usr/bin/env bash
set -euo pipefail

test -z "$(gofmt -l .)"
go mod verify
go vet ./...
go test -count=1 ./...
bash "$(dirname "$0")/check-coverage.sh"
bash -n install.sh run.sh scripts/check-coverage.sh scripts/regression.sh scripts/test-runner.sh scripts/lab/scenario.sh scripts/lab/run-docker-inventory-stress.sh
bash scripts/test-runner.sh

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$tmp/vps-scope-linux-amd64" ./cmd/vps-scope
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$tmp/vps-scope-linux-arm64" ./cmd/vps-scope
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$tmp/vps-scope-lab-helper" ./scripts/lab/net-helper.go
"$tmp/vps-scope-linux-amd64" version
"$tmp/vps-scope-linux-amd64" audit --lang en --profile general --format bundle --output "$tmp/smoke-report" --quiet
"$tmp/vps-scope-linux-amd64" verify "$tmp/smoke-report"
