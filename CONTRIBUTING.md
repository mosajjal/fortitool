# Contributing

Keep each change focused on one format or command contract. Do not include
firmware or other proprietary inputs in the repository.

## Checks

Use Go 1.26.6 with `GOTOOLCHAIN=local`, then run:

```sh
gofmt -l .
go vet ./...
go test ./...
CGO_ENABLED=0 go build -o fortitool ./cmd/fortitool
```

`gofmt -l .` must produce no output. `CGO_ENABLED=0` matters because the
shipped binary must not depend on cgo or system libraries at runtime.

Also run `go test -race ./...`. Changes to fixed-width arithmetic or binary
layouts should pass the Linux/386 tests used by CI:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=386 GO386=sse2 go test ./...
```

If a check cannot run, say so in the pull request.

## Fixtures and real inputs

Tests must use small synthetic, redistributable fixtures built in the test or
by a reviewed generator. They must not depend on locally held firmware,
configuration backups, or external datasets.

Do not commit or attach firmware images, configuration backups, extracted
payloads, recovered keys, secrets, device or account identifiers, or unrelated
logs. Real-input validation should be performed separately and recorded in a
commit message or the README coverage table, as described in `CLAUDE.md`.

Describe what was actually tested. Generated tests and cross-builds do not by
themselves establish real-input or runtime compatibility.

## Command and format changes

Command changes must keep `-h` text, README examples, and
`plugin/skills/fortios-firmware/SKILL.md` in step. Validate both plugin
manifests with the commands in `CLAUDE.md`.

Credit public research next to the algorithm or format detail it informed.
Add focused tests for success and rejection paths, and avoid unrelated cleanup.
