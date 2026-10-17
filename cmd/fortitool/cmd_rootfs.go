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

type rootfsDecision struct {
	Plaintext           []byte
	Family              string
	Cipher              string
	HashOK              bool
	AlreadyPlain        bool
	KernelPayloadSize   int
	KernelPayloadOffset int
	SeedOffset          int
	keyDetail           string
}

func cmdRootfs(ctx context.Context, args []string) error {
	fs := newCommandFlagSet("rootfs", nil)
	out := fs.String("o", "rootfs.gz.dec", "output file")
	showKeys := fs.Bool("show-keys", false, "print recovered key material")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fortitool rootfs -- decrypt supported Fortinet rootfs.gz payloads, auto-detected

Finds the kernel's crypto material and selects a supported rootfs cipher
without a version or architecture flag. FortiOS seed/RSA and static ChaCha20
schemes use flatkc. Protected FAZ/FMG x86-64 vmlinuz kernels use a recovered
XOR key and static AES-128-CTR material; their rootfs SHA-256 digest and
complete XZ/CPIO archive must validate. No external disassembler is needed.

Plain gzip roots and supported XZ CPIO/ext roots are detected and passed
through unchanged. FAZ/FMG roots use vmlinuz in place of flatkc.

USAGE
  fortitool rootfs [-o FILE] <kernel> <rootfs.gz>

  flatkc (or vmlinuz) and rootfs.gz live in the selected boot filesystem.
  Use 'decrypt --boot-only' to obtain them, or 'decrypt' for the full
  pipeline from a supported .out, QCOW2 or single-QCOW2 ZIP input.

FLAGS
  -o FILE      output file (default: rootfs.gz.dec; must not exist)
  --show-keys  print recovered key material (redacted by default)

EXAMPLES
  fortitool rootfs -o rootfs.gz.dec fs/flatkc fs/rootfs.gz
  fortitool rootfs -o rootfs.xz fs/vmlinuz fs/rootfs.gz

OUTPUT
  Prints which crypto family/cipher matched and whether the embedded
  SHA-256 hash check passed, then writes the decrypted rootfs.gz (still
  compressed; use 'decrypt' for automatic rootfs extraction).
  The standalone decrypted file is private to the invoking identity: mode 0600
  on Unix and a protected per-user DACL on Windows.

EXIT CODES
  0  decrypted (or was already compressed plaintext -- check stdout for which)
  1  input/output error, unsupported crypto or invalid rootfs payload
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
		return usagef("usage: fortitool rootfs [-o FILE] <kernel> <rootfs.gz>")
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
	if bytes.HasPrefix(plain, []byte("\xfd7zXZ\x00")) {
		if _, err := classifyRootfsPayload(plain); err != nil {
			return err
		}
	}

	if err := writeNewFile(*out, plain, 0o600); err != nil {
		return err
	}
	fmt.Printf("[+] wrote %s (%d bytes)\n", terminalText(*out), len(plain))
	return nil
}

func decryptRootfsAuto(ctx context.Context, flatkc, rootfsGz []byte, showKeys bool) ([]byte, error) {
	decision, err := decideRootfsCrypto(ctx, flatkc, rootfsGz)
	if err != nil {
		return nil, err
	}
	if decision.AlreadyPlain {
		fmt.Println("[+] rootfs payload is already compressed plaintext (no rootfs crypto)")
		return decision.Plaintext, nil
	}
	fmt.Printf("[*] kernel payload: %d bytes @ kernel image offset 0x%x\n", decision.KernelPayloadSize, decision.KernelPayloadOffset)
	fmt.Printf("[+] seed family=%s cipher=%s hashOK=%v @ kernel offset 0x%x\n",
		terminalText(decision.Family), terminalText(decision.Cipher), decision.HashOK, decision.SeedOffset)
	fmt.Printf("    %s\n", formatRootfsKeyDetail(decision.keyDetail, showKeys))
	return decision.Plaintext, nil
}

func decideRootfsCrypto(ctx context.Context, flatkc, rootfsGz []byte) (*rootfsDecision, error) {
	if len(rootfsGz) >= 2 && rootfsGz[0] == 0x1f && rootfsGz[1] == 0x8b {
		if err := validateGzipMember(rootfsGz, maxStandaloneRootfsExpandedSize); err != nil {
			return nil, fmt.Errorf("validating plain rootfs gzip: %w", err)
		}
		return &rootfsDecision{
			Plaintext: rootfsGz, Family: "none", Cipher: "none", AlreadyPlain: true,
		}, nil
	}

	if bytes.HasPrefix(rootfsGz, []byte("\xfd7zXZ\x00")) {
		return &rootfsDecision{Plaintext: rootfsGz, Family: "none", Cipher: "none", AlreadyPlain: true}, nil
	}

	payload, off, err := kernelpayload.Extract(flatkc)
	if err != nil {
		return nil, fmt.Errorf("extracting kernel payload: %w", err)
	}
	res, err := rootfscrypto.DecryptRootfs(ctx, payload, rootfsGz)
	if err != nil {
		return nil, err
	}
	if len(res.Plaintext) >= 2 && res.Plaintext[0] == 0x1f && res.Plaintext[1] == 0x8b {
		if err := validateGzipMember(res.Plaintext, maxStandaloneRootfsExpandedSize); err != nil {
			return nil, fmt.Errorf("validating decrypted rootfs gzip: %w", err)
		}
	}
	family := "unknown"
	seedOffset := -1
	if res.Seed != nil {
		family = res.Seed.Family
		seedOffset = res.Seed.SeedOffset
	}
	return &rootfsDecision{
		Plaintext: res.Plaintext, Family: family, Cipher: res.Cipher, HashOK: res.HashOK,
		KernelPayloadSize: len(payload), KernelPayloadOffset: off, SeedOffset: seedOffset,
		keyDetail: res.KeyDetail,
	}, nil
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
