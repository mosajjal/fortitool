# fortitool

A single static Go binary and library for decrypting and unpacking Fortinet
firmware: FortiGate/FortiWiFi FortiOS images and tested FortiAnalyzer/FortiManager
KVM installation packages. Supported containers, filesystems and crypto
schemes are detected from their contents, without a product, version or CPU
architecture flag. See [Supported firmware](#supported-firmware) for the
tested products, package types and stages.

The format and crypto readers are implemented in Go. No `openssl`, `xz`,
`tar`, `cpio`, `mount`/`debugfs`, `7z`, `binwalk`, `vmlinux-to-elf`, or Python
is required at runtime. FortiOS config-secret decryption and FortiGuard
PKCS#7 signature inspection are also included.

Historically, decrypting one firmware image meant picking the right tool
out of several version-specific ones (`forticrack`, `fgx`, `forticrack_v8`,
`decrypt-fortigate-rootfs`, ...) and chaining OS binaries by hand.
`fortitool` folds all of that into one command.

## Install

Download the archive for your platform from the
[GitHub releases](https://github.com/mosajjal/fortitool/releases). Each release
includes a SHA-256 checksum file covering every prebuilt-binary archive.
Extract the archive, put `fortitool` (or `fortitool.exe`) on your `PATH`, and
run `fortitool version` to confirm the installed tag.

Alternatively, install with Go:

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
fortitool inspect image.out                    # read-only format/support report
fortitool decrypt -o fmg image.out.kvm.zip     # FAZ/FMG single-QCOW2 package
fortitool decrypt --boot-only -o boot faz.qcow2 # original boot files only
fortitool l1 -o out.img image.out              # outer XOR layer only
fortitool rootfs -o out.gz kernel rootfs.gz    # kernel is flatkc or vmlinuz
fortitool unpack -o outdir archive.tar.xz      # generic gzip+tar / xz+tar
fortitool pkg inspect --content payload sig.x  # verify a PKCS#7 signature
fortitool pkg scan datafs/                     # classify files, find sigs
fortitool config decrypt --stdin < secret.txt  # config-backup ENC secret
fortitool config decrypt --file secret.txt     # file input without argv exposure
```

Every command has a full description, flags, and examples via
`fortitool <command> -h` (or run `fortitool -h` for the command list).
Flags must precede positional arguments — Go's `flag` package doesn't
permute argv the way getopt does.

`inspect` reports one image as stable, human-readable `field: value` lines.
It uses the same L1, disk-layout, required-member, rootfs-crypto and payload
classification decisions as `decrypt`, but does not extract or write anything
and never displays recovered key material. A readable image that is only
partially recognised reports `status: partial`, a `last-successful-stage` and
an `unsupported-stage`, and exits 0 because describing that boundary is a
successful inspection. An absent or inaccessible input exits 1; invalid flags
or argument count exit 2.

`decrypt` and `unpack` publish a completed tree only when the requested
output directory does not already exist. Linux uses an atomic no-replace
rename; other platforms perform a best-effort existence check before the
rename. Staged trees and standalone decrypted files are private to the
invoking identity: mode 0700 or 0600 on Unix, and a protected per-user DACL
on Windows. Archive and filesystem symlinks with absolute targets are rewritten
as confined relative links, so extracted links remain inside the output tree
rather than referring to paths on the host.

For config secrets, prefer `--stdin` or `--file` so the ciphertext does
not appear in process listings or shell history. The direct
`fortitool config decrypt <base64-blob>` form remains available only for
compatibility, and exactly one of the three input sources is accepted.
Input is limited to 1 MiB; surrounding whitespace is trimmed, and the
remaining value must be non-empty and contain no whitespace.

With `pkg inspect --content`, verification succeeds only when the wrapper
contains at least one signer and every `SignerInfo` validates against the
payload. This proves cryptographic integrity using the certificates embedded
in the PKCS#7 wrapper; it does not validate their trust chains to a trusted
root CA.

## Supported firmware

Coverage is specific to the product, package type and processing stage.
FAZ/FMG firmware support does not establish support for their configuration
backup secrets or for other Fortinet products.

### FortiGate and FortiWiFi

Across 167 unique FortiOS images tested, with versions spanning 3.0 through
8.0, L1/header recovery succeeded for every image and matched an independent
decoder byte-for-byte. This covers that stage and tested set only; later
decryption and extraction remain format-dependent, as detailed below.

| Layer | Coverage | Status |
|---|---|---|
| L1 `.out` outer cipher | Supported FortiOS `.out` layouts | **Verified** across the 167-image corpus described above; real FWF-60E 7.4.7/7.4.10/7.4.11 output is byte-identical to an independent decoder |
| rootfs.gz — ChaCha20+RSA+AES-CTR family | 7.4.1–7.4.11 (ARM + x86_64 splits) | ARM path **verified** byte-identical against real firmware; x86_64 splits ported from public write-ups, covered by a synthetic round-trip test, not run against a real x86 sample |
| rootfs.gz — ChaCha20 body (7.4.1–7.4.3 era) | seed-derived key/IV, non-RFC7539 counter | Ported from `fortigate-crypto`/Bishop Fox, covered by a synthetic round-trip test, not run against a real sample of that era |
| rootfs.gz — XOR+RSA+{FORT-RC4,modified-RC4} family | 7.6.x, 8.0 | Ported from public write-ups (`fgx`, `forticrack_v8`), covered by a synthetic round-trip test, not run against a real sample |
| Disk image layouts | appliance MBR+ext3 @512; QCOW2 VM disks; fixed-offset volumes | Appliance path **verified** byte-identical against real firmware; QCOW2/partition and ext4-extent discovery covered by synthetic tests, not run against a real FortiGate VM image |
| ext2/3 filesystem read | FSoC3/ARM appliance MBR+ext3 layout | **Verified** byte-identical against real firmware, including double-indirect block mapping |
| ext4 extent-mapped read | FortiOS 8.0 VM rootfs (xz-compressed ext4 image) | Synthetic round-trip tests only, no real 8.0 sample available |
| tar/gzip/xz unpack | any | **Verified** byte-identical against real firmware |
| PKCS#7 SignedData verify | detached signatures (`.x` files), incl. dual-signed | **Verified** against real signed engine/DB files, both signer chains |
| Config-secret `ENC <base64>` decrypt | all eras | Legacy hardcoded AES-128 key **verified** against real device data through at least 7.2.3 (contrary to common belief it was never rotated at 6.2). The >=7.4 (build 2731) AES-256-CBC key was recovered by RE of the init monolith and **verified against real device backups spanning both eras** — both keys embedded, see [Config-secret keys](#config-secret-keys) |

"Verified" means run against real firmware/config samples and checked
byte-identical or semantically correct output. Everything else is a
faithful port of a documented, working reference implementation, exercised
by this repo's test suite, but not yet run against a real sample of that
specific era — patches with real-firmware validation welcome.

`decrypt` discovers supported ext filesystems in appliance, QCOW2 and
fixed-offset disk layouts. Rootfs containers include gzip tar/CPIO and
XZ CPIO/ext filesystems. Rootfs decompression is limited to 4 GiB.

### FortiAnalyzer and FortiManager

FAZ/FMG KVM installation disks are accepted as bare QCOW2 files or ZIP
packages containing exactly one regular QCOW2 file, limited to 2 GiB after
ZIP decompression. These disks have no L1 firmware header and use `vmlinuz`
instead of `flatkc`. No product/version flag is required.

Each row was tested as both an `FAZ_VM64_KVM` and an `FMG_VM64_KVM`
`.out.kvm.zip` installation package: 24 packages in total. All completed
inspection, full extraction and boot-only extraction. The release/build
labels below are taken from their filenames; the older filenames specify
only `v5` or `v6`, and their minor release numbers have not been established.
Real-image end-to-end runs used the ZIP packages. Bare QCOW2 input shares
the post-unzip reader and is covered separately by synthetic tests.

| Release/build label (both FAZ and FMG) | Main rootfs |
|---|---|
| `v5-build0383` | gzip/newc CPIO |
| `v5-build0786` | gzip/newc CPIO |
| `v5-build1247` | XZ/newc CPIO |
| `v5-build1821` | XZ/newc CPIO |
| `v6-build0485` | XZ/newc CPIO |
| `v6-build1565` | XZ/newc CPIO |
| `v6-build2689` | XZ/newc CPIO |
| `v7.0.16-build0710` | XZ/newc CPIO |
| `v7.2.12-build1721` | XOR-protected kernel, AES-128-CTR XZ/newc CPIO rootfs |
| `v7.4.11.M-build2804` | XOR-protected kernel, AES-128-CTR XZ/newc CPIO rootfs |
| `v7.6.7.M-build3737` | XOR-protected kernel, AES-128-CTR XZ/newc CPIO rootfs |
| `v8.0.1.F-build0189` | XOR-protected kernel, AES-128-CTR XZ/newc CPIO rootfs |

Protected kernels are decoded using material recovered from their x86-64
decompressor stubs. Rootfs candidates must pass the appended plaintext
SHA-256 digest and complete XZ/CPIO validation. These checks confirm key
selection and detect corruption. The digest is unkeyed and does not provide
publisher authentication or protection against deliberate modification.
Each base `init` matched independent libarchive extraction byte for byte.

This coverage is for these KVM installation packages, not FAZ/FMG upgrade
`.out` files, hardware appliances or other Fortinet products.

```sh
fortitool inspect FMG_VM64_KVM-v7.0.16-build0710-FORTINET.out.kvm.zip
fortitool decrypt -o fmg FMG_VM64_KVM-v7.0.16-build0710-FORTINET.out.kvm.zip
fortitool decrypt --boot-only -o boot faz.qcow2
fortitool unpack -o extensions boot/rootfs-ext.tar.xz
```

The full FAZ/FMG extraction preserves the base root filesystem under `rootfs/`.
Nested `bin.tar.xz`, `lib.tar.xz`, `usr.tar.xz`, `migadmin.tar.xz` and
`node-scripts.tar.xz` archives, when present, are unpacked separately under
`layers/rootfs/<archive-name>/`. Additional `syntax.tar.xz`,
`rootfs-ext.tar.xz`, `docker.tar.xz` and `widgets.tar.gz` boot archives go
under `layers/boot/<archive-name>/`. The original archives are retained.
For example, `rootfs/bin/init` and `layers/rootfs/bin.tar.xz/bin/init` can
contain different bootstrap and application programs. These outputs retain
both versions for static analysis; they do not represent a merged bootable
filesystem. Existing FortiGate extraction continues to merge its nested
archives into `rootfs/`.

`--boot-only` extracts readable directories, regular files and symlinks from
the selected boot filesystem without rootfs decryption or archive expansion.
The filesystem reader skips unreadable entries and special files such as
device/FIFO nodes, so success does not certify a complete filesystem copy.
This provides access to readable additional archives on newer images.
Normal `decrypt` remains all-or-nothing and publishes no output when the
main rootfs is unsupported.
`inspect` reports the last recognised stage; a complete report does not
validate nested archives or prove that the full extraction will succeed.

## Config-secret keys

`fortitool config decrypt` handles both eras of FortiOS config-backup
secrets with their hardcoded keys embedded:

* **Pre-7.4 (6.2–7.2.x):** the AES-128 key published with CVE-2019-6693
  in 2019.
* **>=7.4 (build 2731):** an AES-256 key recoverable by reverse
  engineering the firmware's init monolith, where it ships as a static
  constant in every image of that era. It is included here on the same
  basis as the firmware-unpacking material and the CVE-2019-6693 key:
  anyone with any image of the era can derive it in an afternoon, and
  public precedent treats such constants as fair-published.

Practical consequence either way: **a FortiOS config backup should be
treated as plaintext-adjacent.** Don't post one to forums or ticket
systems, and use the optional `private-data-encryption` passphrase
feature if a backup may travel.

## How the auto-detection works

The input container determines whether an L1 firmware header is required.
QCOW2 disks (bare or gzip-wrapped) and single-QCOW2 ZIP packages use the
existing disk and filesystem readers. QCOW2 disks need no L1 header; when a
validated header is present, its identity is retained. Other inputs require
a validated L1 header. Volume selection requires a
`flatkc` or `vmlinuz` kernel and `rootfs.gz`; plain gzip/XZ roots skip crypto.

For FortiOS seed/RSA schemes, `fortitool` locates the
32-byte seed and 270-byte obfuscated RSA public key FortiOS hides in the
kernel by exploiting a structural fact: the recovered key always decrypts
to a known ASN.1 DER prefix. Scanning for windows that satisfy that
constraint — across both known obfuscation families (XOR and ChaCha20,
several observed key-derivation splits, contiguous and near-contiguous
layouts) — finds the right material without disassembling anything
(no objdump/miasm/Ghidra needed). The same idea locates the outer L1 XOR
key via a known-plaintext attack, and picks the rootfs body cipher
(AES-CTR / FORT-RC4 / modified-RC4) through candidate validation. Static
ChaCha20 material is selected by complete gzip/tar validation.

Protected FAZ/FMG x86-64 `vmlinuz` images carry repeating XOR material in
their decompressor stub. The decoded kernel must pass gzip integrity and
ELF bounds checks. Adjacent AES-128 key/IV candidates in that kernel are
selected only when the rootfs plaintext matches its stored SHA-256 digest
and passes complete XZ/CPIO validation. The keys and offsets are recovered
from each image, rather than selected from a product/version table.

## Package layout

```
internal/l1            outer .out XOR cipher (known-plaintext attack)
internal/kernelpayload  flatkc / protected x86-64 vmlinuz -> kernel bytes
internal/rootfscrypto   seed/RSA and static-material scanners + rootfs ciphers
internal/qcow2          read-only qcow2 (VM disk) reader
internal/diskimage      read-only ext2/ext3/ext4 (MBR partitions, fixed-offset
                        volumes, extent-mapped inodes, ExtractAll dump)
internal/archive        tar/newc CPIO, gzip/xz unpacking (stdlib + pure-Go xz)
internal/pkcs7          PKCS#7 SignedData parse + detached-signature verify
internal/configsecret   config-backup ENC secret decrypt, all eras
cmd/fortitool           CLI wiring the above into the commands above
```

Every package ships `go test`-able unit tests using synthetic, locally
generated fixtures (self-signed certs, hand-built ext2 images, round-trip
crypto vectors) — no copyrighted firmware is needed to run or verify this
code. Run `go test ./...`.

## Acknowledgments

`fortitool` exists because several researchers already did the hard part —
finding and documenting these crypto schemes in the first place. Every
algorithm below is a from-scratch Go reimplementation written from reading
their public writeups/source (not copied code — several of these projects
are GPL-licensed, which this MIT-licensed project doesn't inherit from
because no source was copied — but full credit is owed regardless):

- **[BishopFox/forticrack](https://github.com/BishopFox/forticrack)** (GPL-3.0) —
  the L1 `.out` known-plaintext attack this project's `internal/l1` is a
  reimplementation of, plus the original writeups
  ["Breaking Fortinet Firmware Encryption"](https://bishopfox.com/blog/breaking-fortinet-firmware-encryption)
  and ["Further Adventures in Fortinet Decryption"](https://bishopfox.com/blog/further-adventures-in-fortinet-decryption)
  (ChaCha20 rootfs scheme, 7.4.1–7.4.3).
- **[hacefresko/forticrack_v8](https://github.com/hacefresko/forticrack_v8)** —
  the FortiOS 8.0 FORT-RC4 rootfs cipher (both FGT/FFW silicon variants)
  `internal/rootfscrypto`'s `fortRC4` is based on.
- **[Bishop Fox, "A Brief Look at FortiJump"](https://bishopfox.com/blog/a-look-at-fortijump-cve-2024-47575)**
  and **[Rapid7, "Rapid7 Analysis: CVE-2024-47575"](https://www.rapid7.com/blog/post/ra-cve-2024-47575-analysis/)** —
  the FortiManager kernel XOR and static AES-128-CTR format descriptions
  used for the independent FAZ/FMG decoder implementation.
- **[hackintoanetwork/fgx](https://github.com/hackintoanetwork/fgx)** (GPL-3.0) —
  the FortiOS 7.6.x modified-RC4 rootfs cipher, and the disassembly-free
  seed/RSA-key scanning approach (contiguous + near-contiguous layouts)
  this project's universal scanner generalizes.
- **[noways-io/fortigate-crypto](https://github.com/noways-io/fortigate-crypto)** (Apache-2.0) —
  the original C reference for the 7.4.2/7.4.3 x86_64 ChaCha20 rootfs
  key-derivation splits.
- **[RandoriSec](https://blog.randorisec.fr/fortigate-rootfs-decryption/)** —
  the 7.4.7+ stripped-kernel rootfs decryption writeup this project's ARM
  adaptation (independently found via this project's earlier Python
  tooling) builds on the same technique from.
- **[gquere/CVE-2019-6693](https://github.com/gquere/CVE-2019-6693)** — the
  original disclosure and reference decryptor for the legacy config-secret
  AES-CBC scheme `internal/configsecret` implements (and whose real
  applicability range — never rotated at 6.2, actually rotated at 7.4 —
  this project corrected via device-level reverse engineering).
If you're one of the people behind these projects and want different
attribution, open an issue.

## Legal / responsible use

Only use this against firmware for hardware you own, for security research
or interoperability purposes. Fortinet's EULA contractually prohibits
reverse engineering; the DMCA §1201 security-research exemption (in the
US) covers good-faith research on lawfully-owned devices. Don't
redistribute firmware images or derived keys, and don't run this against
anything you don't own or have explicit authorization to test.

## Contributing

Issues and PRs welcome, especially validation of the unverified FortiOS
paths above, FAZ/FMG upgrade `.out` packages and hardware images, or samples
from other Fortinet product types. Report the exact product, version/build,
package type and last successful stage; keep firmware and extracted files
private. See [CONTRIBUTING.md](CONTRIBUTING.md) for the required checks and
fixture policy.

## License

MIT — see [LICENSE](LICENSE).
