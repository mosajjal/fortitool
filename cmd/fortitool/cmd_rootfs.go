package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mosajjal/fortitool/internal/kernelpayload"
	"github.com/mosajjal/fortitool/internal/rootfscrypto"
)

const maxStandaloneRootfsExpandedSize int64 = 4 << 30

func cmdRootfs(ctx context.Context, args []string) error {
	fs := newCommandFlagSet("rootfs", nil)
	out := fs.String("o", "rootfs.gz.dec", "output file")
	showKeys := fs.Bool("show-keys", false, "print recovered key material")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fortitool rootfs -- decrypt rootfs.gz, any known FortiOS era, auto-detected

Every FortiOS rootfs.gz crypto scheme from 7.4.1 through 8.0 hides a
32-byte seed and a 270-byte obfuscated RSA public key somewhere in the
kernel (flatkc), used to unwrap a per-image AES/RC4 key carried in
rootfs.gz's own trailing 256-byte signature. This command scans for that
material WITHOUT disassembly (no objdump/miasm/Ghidra needed) by
exploiting that the recovered key always decrypts to a known ASN.1 DER
prefix, covering two obfuscation families and picks whichever body cipher
(AES-CTR / FORT-RC4 / modified-RC4) actually produces a valid gzip stream
-- no version or CPU architecture flag required.

Pre-7.4.1 images have NO rootfs encryption (plain gzip+cpio/tar); that
case is detected and passed through unchanged.

USAGE
  fortitool rootfs [-o FILE] <flatkc> <rootfs.gz>

  flatkc and rootfs.gz are the two files that live at the root of the
  ext3 volume inside a decrypted (L1-layer) firmware image -- extract
  them yourself, or use 'fortitool decrypt' for the full one-shot
  pipeline starting from the raw .out file.

FLAGS
  -o FILE      output file (default: rootfs.gz.dec; must not exist)
  --show-keys  print recovered key material (redacted by default)

EXAMPLE
  fortitool rootfs -o rootfs.gz.dec fs/flatkc fs/rootfs.gz

OUTPUT
  Prints which crypto family/cipher matched and whether the embedded
  SHA-256 hash check passed, then writes the decrypted rootfs.gz (still
  gzip-compressed tar -- pipe it to 'fortitool unpack' to extract it).
  The standalone decrypted file is private to the invoking identity: mode 0600
  on Unix and a protected per-user DACL on Windows.

EXIT CODES
  0  decrypted (or was already plain gzip -- check stdout for which)
  1  no seed/RSA-key material found, or none of the known body ciphers
     produced valid output -- likely an unsupported crypto era
  2  invalid flags or wrong number of positional arguments
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usage(err)
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return usagef("usage: fortitool rootfs [-o FILE] <flatkc> <rootfs.gz>")
	}

	flatkc, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	rootfsGz, err := os.ReadFile(fs.Arg(1))
	if err != nil {
		return err
	}

	plain, err := decryptRootfsAuto(ctx, flatkc, rootfsGz, *showKeys)
	if err != nil {
		return err
	}
	if err := writeNewFile(*out, plain, 0o600); err != nil {
		return err
	}
	fmt.Printf("[+] wrote %s (%d bytes)\n", terminalText(*out), len(plain))
	return nil
}

// decryptRootfsAuto handles both encrypted (7.4.x+) and plain (<=7.4.0)
// rootfs.gz: plain images are already valid gzip and need no crypto at all.
func decryptRootfsAuto(ctx context.Context, flatkc, rootfsGz []byte, showKeys bool) ([]byte, error) {
	if len(rootfsGz) >= 2 && rootfsGz[0] == 0x1f && rootfsGz[1] == 0x8b {
		if err := validateGzipMember(rootfsGz, maxStandaloneRootfsExpandedSize); err != nil {
			return nil, fmt.Errorf("validating plain rootfs gzip: %w", err)
		}
		fmt.Println("[+] rootfs.gz is already plain gzip (pre-7.4.1 image, no rootfs crypto)")
		return rootfsGz, nil
	}

	payload, off, err := kernelpayload.Extract(flatkc)
	if err != nil {
		return nil, fmt.Errorf("extracting kernel payload from flatkc: %w", err)
	}
	fmt.Printf("[*] kernel payload: %d bytes @ flatkc offset 0x%x\n", len(payload), off)

	res, err := rootfscrypto.DecryptRootfs(ctx, payload, rootfsGz)
	if err != nil {
		return nil, err
	}
	fmt.Printf("[+] seed family=%s cipher=%s hashOK=%v @ kernel offset 0x%x\n",
		terminalText(res.Seed.Family), terminalText(res.Cipher), res.HashOK, res.Seed.SeedOffset)
	fmt.Printf("    %s\n", formatRootfsKeyDetail(res.KeyDetail, showKeys))
	if len(res.Plaintext) >= 2 && res.Plaintext[0] == 0x1f && res.Plaintext[1] == 0x8b {
		if err := validateGzipMember(res.Plaintext, maxStandaloneRootfsExpandedSize); err != nil {
			return nil, fmt.Errorf("validating decrypted rootfs gzip: %w", err)
		}
	}
	return res.Plaintext, nil
}

func validateGzipMember(data []byte, maxExpanded int64) error {
	if maxExpanded < 0 {
		return fmt.Errorf("invalid gzip expansion limit %d", maxExpanded)
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer r.Close()
	r.Multistream(false)
	n, err := io.Copy(io.Discard, io.LimitReader(r, maxExpanded+1))
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	if n > maxExpanded {
		return fmt.Errorf("gzip expands past %d bytes", maxExpanded)
	}
	return nil
}
