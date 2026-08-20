# fortitool

A single static Go binary that decrypts and unpacks Fortinet FortiOS
firmware end to end — no `openssl`, `xz`, `tar`, `cpio`, `mount`/`debugfs`,
`7z`, `binwalk`, `vmlinux-to-elf`, or Python at runtime. Every format
(gzip, tar, xz, ext2/3, ASN.1/PKCS#7) and every crypto layer FortiOS has
shipped (the outer XOR cipher, ChaCha20+RSA+AES-CTR, XOR+RSA+FORT-RC4,
modified-RC4, legacy config-secret AES-CBC) is implemented in Go and
auto-detected — no version, model, or CPU architecture flag needed.

Historically, decrypting one firmware image meant picking the right tool
out of several version-specific ones (`forticrack`, `fgx`, `forticrack_v8`,
`decrypt-fortigate-rootfs`, ...) and chaining OS binaries by hand.
`fortitool` folds all of that into one command.

## Install

```sh
go install github.com/mosajjal/fortitool/cmd/fortitool@latest
```

Or build from source:

```sh
git clone https://github.com/mosajjal/fortitool
cd fortitool
CGO_ENABLED=0 go build -o fortitool ./cmd/fortitool
```

`CGO_ENABLED=0` matters if you want the fully-static binary this project
promises — without it, Go links against glibc for the (unused) net
resolver. Verify with `file fortitool` (should say "statically linked") or
`ldd fortitool` (should say "not a dynamic executable").

## Usage

```sh
fortitool decrypt -o outdir image.out          # full pipeline, one command
fortitool l1 -o out.img image.out              # outer XOR layer only
fortitool rootfs -o out.gz flatkc rootfs.gz    # rootfs crypto layer only
fortitool unpack -o outdir archive.tar.xz      # generic gzip+tar / xz+tar
fortitool pkg inspect sig.x --content payload  # verify a PKCS#7 signature
fortitool pkg scan datafs/                     # classify files, find sigs
fortitool config decrypt <base64-blob>         # config-backup ENC secret
```

Every command has a full description, flags, and examples via
`fortitool <command> -h` (or run `fortitool -h` for the command list).
Flags must precede positional arguments — Go's `flag` package doesn't
permute argv the way getopt does.

## Supported firmware

| Layer | Coverage | Status |
|---|---|---|
| L1 `.out` outer cipher | v6.x through 8.0, all product lines | **Verified** against 3 real FWF-60E images (7.4.7/7.4.10/7.4.11), byte-identical |
| rootfs.gz — ChaCha20+RSA+AES-CTR family | 7.4.1–7.4.11 (ARM + x86_64 splits) | ARM path **verified** byte-identical against real firmware; x86_64 splits ported from public write-ups, covered by a synthetic round-trip test, not run against a real x86 sample |
| rootfs.gz — XOR+RSA+{FORT-RC4,modified-RC4} family | 7.6.x, 8.0 | Ported from public write-ups (`fgx`, `forticrack_v8`), covered by a synthetic round-trip test, not run against a real sample |
| ext2/3 filesystem read | FSoC3/ARM appliance MBR+ext3 layout | **Verified** byte-identical against real firmware (including double-indirect block mapping, exercised by a 56MB file) |
| tar/gzip/xz unpack | any | **Verified** byte-identical against real firmware |
| PKCS#7 SignedData verify | detached signatures (`.x` files), incl. dual-signed | **Verified** against 13 real signed engine/DB files, both signer chains |
| Config-secret `ENC <base64>` decrypt | legacy hardcoded key | **Verified** against real device data. Contrary to common belief, this key was never rotated at FortiOS 6.2 — it still works through at least 7.2.3. It changed at 7.4 (build 2731) to a key that has not been identified; that era is detected (an unencrypted 8-byte trailer marker) and reported rather than silently mis-decrypted |

"Verified" means run against real firmware/config samples and checked
byte-identical or semantically correct output. Everything else is a
faithful port of a documented, working reference implementation, exercised
by this repo's test suite, but not yet run against a real sample of that
specific era — patches with real-firmware validation welcome.

Currently `decrypt` (the full pipeline) targets the FSoC3/ARM appliance
MBR+ext3 partition layout. x86/VM firmware images may use a different
layout; use `l1` and `rootfs` as building blocks against extracted
partition files if the one-shot pipeline doesn't apply to your image.

## How the auto-detection works

Rather than requiring a version/architecture flag, `fortitool` locates the
32-byte seed and 270-byte obfuscated RSA public key FortiOS hides in the
kernel by exploiting a structural fact: the recovered key always decrypts
to a known ASN.1 DER prefix. Scanning for windows that satisfy that
constraint — across both known obfuscation families (XOR and ChaCha20,
several observed key-derivation splits, contiguous and near-contiguous
layouts) — finds the right material without disassembling anything
(no objdump/miasm/Ghidra needed). The same idea locates the outer L1 XOR
key via a known-plaintext attack, and picks the rootfs body cipher
(AES-CTR / FORT-RC4 / modified-RC4) by trying each against a probe and
checking for the gzip magic bytes in the output.

## Package layout

```
internal/l1            outer .out XOR cipher (known-plaintext attack)
internal/kernelpayload  flatkc -> decompressed kernel bytes
internal/rootfscrypto   seed/RSA-key scanner + all rootfs.gz body ciphers
internal/diskimage      read-only ext2/ext3 (MBR-stripped partition -> files)
internal/archive        tar/gzip/xz unpacking (stdlib + pure-Go xz)
internal/pkcs7          PKCS#7 SignedData parse + detached-signature verify
internal/configsecret   config-backup ENC secret decrypt
cmd/fortitool           CLI wiring the above into the commands above
```

Every package ships `go test`-able unit tests using synthetic, locally
generated fixtures (self-signed certs, hand-built ext2 images, round-trip
crypto vectors) — no copyrighted firmware is needed to run or verify this
code. Run `go test ./...`.

## Legal / responsible use

Only use this against firmware for hardware you own, for security research
or interoperability purposes. Fortinet's EULA contractually prohibits
reverse engineering; the DMCA §1201 security-research exemption (in the
US) covers good-faith research on lawfully-owned devices. Don't
redistribute firmware images or derived keys, and don't run this against
anything you don't own or have explicit authorization to test.

## Contributing

Issues and PRs welcome, especially real-firmware validation of the
not-yet-verified paths in the table above (7.6.x, 8.0, x86_64 builds), or
progress on the unidentified >=7.4 config-secret key. Run `go build ./...
&& go vet ./... && go test ./...` before submitting.

## License

MIT — see [LICENSE](LICENSE).
