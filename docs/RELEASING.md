# Releasing

Releases are built by GitHub Actions from semantic-version tags.

## Before tagging

1. Make sure `main` is clean and CI and CodeQL are passing.
2. Review `CHANGELOG.md` and move the relevant entries from `Unreleased` into a new version section.
3. Run `go test -race ./...` and `go vet ./...` on Linux.
4. Confirm both cross-builds succeed and the deterministic third-party notice generator covers every linked module.
5. Confirm no real host reports or identifying values are tracked.

## Create a release

```bash
git tag -a v0.1.0 -m "VPS Scope v0.1.0"
git push origin v0.1.0
```

The release workflow validates the tag, runs the test suite, builds Linux amd64 and arm64 binaries, generates the linked-module license notices, writes `SHA256SUMS`, signs every distributed payload, attests both binaries, and re-verifies the exact staged file set before creating the GitHub Release.

Afterward, download every asset from the Release page, verify the complete checksum set and both binary attestations, inspect the license notice, and run `vps-scope version` on each architecture available for testing.
