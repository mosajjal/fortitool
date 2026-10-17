---
name: fortios-firmware
description: Decrypt and unpack supported Fortinet firmware using the fortitool CLI (github.com/mosajjal/fortitool). Use for FortiGate/FortiWiFi ".out" firmware or FortiAnalyzer/FortiManager KVM QCOW2 and single-disk ZIP packages; extracting flatkc, vmlinuz, rootfs.gz or the boot filesystem; inspecting FortiGuard PKCS#7 ".x" signatures or datafs files; or decrypting `set <field> ENC <base64>` secrets from FortiOS config backups.
---

Only ever run this against firmware or config backups the user owns or is
explicitly authorized to analyze (their own hardware, an authorized
pentest/research engagement). Refuse or ask first if that's unclear.

## Get the binary

Check `fortitool -h` first. If not on PATH, download the archive for the current
platform from https://github.com/mosajjal/fortitool/releases, verify it against
the release's SHA-256 checksum file, and put the extracted binary on PATH.

Alternatively, install with Go:

```sh
go install github.com/mosajjal/fortitool/cmd/fortitool@latest
```

or build from source (`git clone https://github.com/mosajjal/fortitool && cd fortitool && CGO_ENABLED=0 go build -o fortitool ./cmd/fortitool`).

## Commands

| Command | Does |
|---|---|
| `fortitool decrypt -o OUTDIR image` | Full extraction of supported `.out`, QCOW2 or single-QCOW2 ZIP inputs |
| `fortitool decrypt --boot-only -o OUTDIR image` | Extract readable boot files, preserving encoded rootfs and additional archives; skips unreadable entries and special files |
| `fortitool inspect image` | Describe one image and its last recognised stage without extracting files or showing keys |
| `fortitool l1 -o out.img image.out` | Outer XOR layer only |
| `fortitool rootfs -o out.gz kernel rootfs.gz` | rootfs.gz crypto layer using flatkc or vmlinuz |
| `fortitool unpack -o outdir archive` | Generic tar / gzip+tar / xz+tar extraction |
| `fortitool pkg scan datafs/` | Classify files in a directory, find PKCS#7 signatures |
| `fortitool pkg inspect --content payload sig.x` | Verify every signer in a detached PKCS#7 signature (integrity only; no trust-chain validation) |
| `fortitool config decrypt --stdin` | Decrypt a config-backup `ENC` secret without exposing it in argv |
| `fortitool config decrypt --file ciphertext.txt` | Decrypt a config-backup `ENC` secret from a file |

Every crypto layer auto-detects its era/scheme (no version or CPU
architecture flag). Run `fortitool <command> -h` for that command's full
flags, behavior notes, and worked examples before using it -- the help
text is the authoritative reference, more detailed than this file.

**Flags must precede positional arguments** (`fortitool decrypt -o outdir
image.out`, not `fortitool decrypt image.out -o outdir` -- Go's flag
parser doesn't permute argv).

## Notes

- `inspect` is read-only and single-image. A readable partial or unsupported
  image exits 0 with `status: partial`, `last-successful-stage` and
  `unsupported-stage`; absent or inaccessible input exits 1. It has no
  `--show-keys`, output-directory, JSON or batch option.
- The 24 tested FAZ/FMG KVM packages support full extraction, including
  protected kernels and AES-128-CTR rootfs in 7.2.12, 7.4.11, 7.6.7 and
  8.0.1. See the README for exact builds. This does not establish support
  for FAZ/FMG upgrade `.out` packages or hardware-appliance images.
- FAZ/FMG output retains base files in `rootfs/` and extracts archives into
  `layers/rootfs/<archive-name>/` and `layers/boot/<archive-name>/`. Different
  versions of the same path are preserved; do not assume a merged bootable
  filesystem or that the base `bin/init` is the application binary.
- `decrypt` discovers supported ext filesystems in raw MBR-partitioned,
  qcow2, and fixed-offset disk layouts. Its output directory must not already
  exist and is published only after the requested extraction succeeds.
  `--boot-only` skips rootfs decoding and archive expansion; unreadable entries
  and special files are skipped, so it does not certify a complete copy.
- `config decrypt` auto-detects and handles both known key eras (legacy,
  through FortiOS 7.2.3, and >=7.4/build 2731) -- no flags needed. If it
  still reports an unrecognized format, the field's blob layout isn't one
  of the two known ones yet, not a version issue.
- Prefer `config decrypt --stdin` or `--file` so ciphertext does not appear
  in process listings or shell history. Direct argv input is retained only
  for compatibility; select exactly one source. Input is limited to 1 MiB;
  surrounding whitespace is trimmed, and the remaining value must be non-empty
  and contain no whitespace.
- Exit code 0 = succeeded (including "already cleartext" / recognized
  unsupported cases where relevant); 1 = failed; 2 = usage error.
- Decrypted files and staged output trees are private to the invoking identity:
  mode 0600 or 0700 on Unix, and a protected per-user DACL on Windows.
  Destinations must not already exist, and recovered keys are redacted unless
  `--show-keys` is explicitly requested.
