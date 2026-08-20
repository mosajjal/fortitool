# fortitool

Single static Go binary/library that decrypts and unpacks FortiOS firmware
end-to-end. See README.md for the full pitch, supported-firmware table, and
acknowledgments. This file is for working on the code itself.

## Build / test

```sh
CGO_ENABLED=0 go build -o fortitool ./cmd/fortitool   # the actual shippable binary
go vet ./...
go test ./...
gofmt -l .   # must be empty
```

Always run all four before considering a change done. `CGO_ENABLED=0`
matters: without it the binary links dynamically against glibc and breaks
the "no OS packages at runtime" promise this whole project exists for.

## Architecture

```
internal/l1            outer .out XOR cipher (known-plaintext attack)
internal/kernelpayload  flatkc -> decompressed kernel bytes
internal/rootfscrypto   seed/RSA-key scanner + all rootfs.gz body ciphers
internal/diskimage      read-only ext2/ext3 (MBR-stripped partition -> files)
internal/archive        tar/gzip/xz unpacking (stdlib + pure-Go xz)
internal/pkcs7          PKCS#7 SignedData parse + detached-signature verify
internal/configsecret   config-backup ENC secret decrypt
cmd/fortitool           CLI wiring
```

Every `internal/*` package is self-contained and has its own `_test.go`
using synthetic fixtures built in-test (hand-rolled ext2 images, locally
generated certs, round-trip crypto vectors) — never real firmware. Don't
add a dependency on real firmware/config samples to any test; if you need
to validate against real data, do that manually and note the result in a
commit message or the README's coverage table, not in `go test`.

## Conventions

- No comments explaining what code does — only non-obvious invariants
  (a hidden format constraint, why a magic number is what it is, a
  workaround for a specific quirk). If you're citing a source (a blog
  post, a prior tool, a CVE), that's worth a comment; restating the code
  in English is not.
- When a crypto/format detail was ported from prior public research
  (BishopFox/forticrack, hacefresko/forticrack_v8, hackintoanetwork/fgx,
  noways-io/fortigate-crypto, RandoriSec, gquere/CVE-2019-6693), credit it
  inline where the algorithm lives, not just in the README. See existing
  doc comments in `internal/l1`, `internal/rootfscrypto`, and
  `internal/configsecret` for the pattern.
- Every `cmd/fortitool/cmd_*.go` subcommand sets `fs.Usage` to a full,
  worked-example help text (not just a flag listing) and uses
  `flag.ContinueOnError` so `-h`/`--help` exits 0. Match that pattern for
  any new subcommand — this CLI is meant to be self-documenting enough
  that an agent invoking it blind (no source access) can use it correctly
  from `--help` alone.
- Prefer extending the auto-detection (the seed/RSA scanner in
  `internal/rootfscrypto`, the layout detection in `internal/configsecret`)
  over adding a version/model/architecture flag. The entire point of this
  tool is that the user shouldn't have to know which FortiOS era they're
  looking at.

## Repo layout beyond the Go module

This repo is also a Claude Code plugin marketplace: `.claude-plugin/marketplace.json`
at the root lists one plugin sourced from `./plugin` (kept separate from
the Go module and this file on purpose -- ships only what an agent needs
to *use* the built binary, not develop it). `plugin/skills/fortios-firmware/SKILL.md`
teaches that. If you change the CLI's command surface, update the skill's
command table too. Validate with:

```sh
claude plugin validate .claude-plugin/marketplace.json --strict
claude plugin validate plugin/.claude-plugin/plugin.json --strict
```
