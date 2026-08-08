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

The release workflow validates the tag, runs the test suite, builds Linux amd64 and arm64 binaries, copies the tagged runner and installer, generates the linked-module license notices, writes `SHA256SUMS`, signs all seven distributed payloads, attests both binaries, and verifies the exact fourteen-file staged set. It then creates a draft Release, downloads all assets from GitHub, repeats the exact-set, checksum, and seven-signature verification, and publishes only if the round trip succeeds. If a later step fails, the workflow deletes only the still-draft Release whose database ID was recorded by that run; it never deletes the Git tag, an existing draft that the run did not create, or a published Release.

Afterward, verify both binary attestations, inspect the license notice, and run `vps-scope version` on each architecture available for testing. Also confirm that the README one-line runner resolves to the newly published signed `run.sh`; it must not be changed to a mutable branch URL.
