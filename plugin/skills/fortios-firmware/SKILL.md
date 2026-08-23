---
name: fortios-firmware
description: Decrypt and unpack Fortinet FortiOS firmware images and config-backup secrets using the fortitool CLI (github.com/mosajjal/fortitool). Use when the user has a FortiGate/FortiWiFi ".out" firmware image and wants it decrypted/unpacked, needs to extract or read flatkc/rootfs.gz/the ext3 volume from FortiOS firmware, wants to verify a FortiGuard PKCS#7 ".x" signature or inspect a datafs directory, or wants to decrypt a `set <field> ENC <base64>` secret from a FortiOS config backup.
---

Only ever run this against firmware or config backups the user owns or is
explicitly authorized to analyze (their own hardware, an authorized
pentest/research engagement). Refuse or ask first if that's unclear.

## Get the binary

Check `fortitool -h` first. If not on PATH:

```sh
go install github.com/mosajjal/fortitool/cmd/fortitool@latest
```

or build from source (`git clone https://github.com/mosajjal/fortitool && cd fortitool && CGO_ENABLED=0 go build -o fortitool ./cmd/fortitool`).

## Commands

| Command | Does |
|---|---|
| `fortitool decrypt -o OUTDIR image.out` | Full pipeline: raw `.out` -> unpacked rootfs, one shot. Try this first for a firmware image. |
| `fortitool l1 -o out.img image.out` | Outer XOR layer only |
| `fortitool rootfs -o out.gz flatkc rootfs.gz` | rootfs.gz crypto layer only |
| `fortitool unpack -o outdir archive` | Generic gzip+tar / xz+tar extraction |
| `fortitool pkg scan datafs/` | Classify files in a directory, find PKCS#7 signatures |
| `fortitool pkg inspect --content payload sig.x` | Verify every signer in a detached PKCS#7 signature (integrity only; no trust-chain validation) |
| `fortitool config decrypt <base64-blob>` | Decrypt a config-backup `ENC` secret |

Every crypto layer auto-detects its era/scheme (no version or CPU
architecture flag). Run `fortitool <command> -h` for that command's full
flags, behavior notes, and worked examples before using it -- the help
text is the authoritative reference, more detailed than this file.

**Flags must precede positional arguments** (`fortitool decrypt -o outdir
image.out`, not `fortitool decrypt image.out -o outdir` -- Go's flag
parser doesn't permute argv).

## Notes

- `decrypt` currently targets the FSoC3/ARM appliance MBR+ext3 partition
  layout. If it fails partway through on an x86/VM image, fall back to
  `l1` + `rootfs` as building blocks against the extracted partition.
- `config decrypt` auto-detects and handles both known key eras (legacy,
  through FortiOS 7.2.3, and >=7.4/build 2731) -- no flags needed. If it
  still reports an unrecognized format, the field's blob layout isn't one
  of the two known ones yet, not a version issue.
- Exit code 0 = succeeded (including "already cleartext" / recognized
  unsupported cases where relevant); 1 = failed; 2 = usage error.
