package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mosajjal/fortitool/internal/archive"
	"github.com/mosajjal/fortitool/internal/diskimage"
	"github.com/mosajjal/fortitool/internal/l1"
)

// nestedTarXZMembers are the tar+xz archives FortiOS nests inside the outer
// rootfs tar; each is extracted into its own subdirectory named after it.
var nestedTarXZMembers = []string{"bin.tar.xz", "usr.tar.xz", "migadmin.tar.xz", "node-scripts.tar.xz"}

func cmdDecrypt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	outDir := fs.String("o", "", "output directory (required)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fortitool decrypt -- full pipeline: raw .out -> unpacked rootfs, one command

Runs the whole chain in order, auto-detecting the crypto era at each
layer (no version/model/architecture flag needed):
  1. gunzip the outer .out wrapper
  2. L1 XOR decrypt (known-plaintext attack, or detect already-cleartext)
  3. read the ext3 volume at MBR offset 512 (pure Go, no mount/debugfs)
  4. locate flatkc + rootfs.gz, extract datafs.tar.gz/devicetree.dtb/etc
     alongside them if present
  5. decrypt rootfs.gz (any known FortiOS 7.4.x-8.0 scheme)
  6. unpack the rootfs tar, then merge in any nested bin.tar.xz/
     usr.tar.xz/migadmin.tar.xz/node-scripts.tar.xz members, then unpack
     datafs.tar.gz if present

This currently targets the FSoC3/ARM appliance MBR+ext3 image layout
(verified end-to-end against real FWF-60E firmware) -- x86/VM images may
use a different partition layout not yet handled here; use 'fortitool l1'
+ 'fortitool rootfs' as building blocks if this fails partway through.

USAGE
  fortitool decrypt -o OUTDIR <image.out>

FLAGS
  -o OUTDIR   output directory (required) -- created if missing

EXAMPLE
  fortitool decrypt -o work/v7411 FWF_60E-v7.4.11-build2878-FORTINET.out

OUTPUT LAYOUT (under OUTDIR)
  flatkc, rootfs.gz.dec, datafs.tar.gz, devicetree.dtb, ...  (raw extracted files)
  rootfs/                                                    (unpacked rootfs tree)
  rootfs/bin/init                                            (the FortiOS monolith,
                                                                if bin.tar.xz was present)
  datafs/                                                     (unpacked datafs.tar.gz,
                                                                if present)

EXIT CODES
  0  full pipeline succeeded
  1  failed at some stage -- stdout shows which step ([1/6]..[6/6]) and
     the error indicates why (wrong file, unsupported crypto era, etc.)
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() < 1 || *outDir == "" {
		fs.Usage()
		return fmt.Errorf("missing required argument or -o flag")
	}
	inPath := fs.Arg(0)
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}

	fmt.Printf("[1/6] loading %s\n", inPath)
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	img, err := gunzipOuter(raw)
	if err != nil {
		return fmt.Errorf("outer gunzip: %w", err)
	}
	fmt.Printf("      %d bytes\n", len(img))

	fmt.Println("[2/6] L1 outer-layer decryption")
	plain, key, wasEncrypted, ok := l1.DecryptAuto(ctx, img)
	if !ok {
		return fmt.Errorf("no valid L1 key found")
	}
	if wasEncrypted {
		fmt.Printf("      key: %s\n", key)
	} else {
		fmt.Println("      already cleartext")
	}

	fmt.Println("[3/6] reading ext3 volume (MBR @512)")
	if len(plain) < 512 {
		return fmt.Errorf("decrypted image too small to contain an MBR + ext3 volume")
	}
	part := plain[512:]
	volume, err := diskimage.Open(part)
	if err != nil {
		return fmt.Errorf("ext3 open: %w", err)
	}
	entries, err := volume.ReadDir("")
	if err != nil {
		return fmt.Errorf("ext3 root readdir: %w", err)
	}
	fmt.Printf("      %d root entries\n", len(entries))

	extract := func(name string) ([]byte, error) {
		for _, e := range entries {
			if e.Name == name {
				return volume.ReadFile(name)
			}
		}
		return nil, nil // absent -- not every image carries every optional file
	}

	flatkc, err := extract("flatkc")
	if err != nil {
		return fmt.Errorf("reading flatkc: %w", err)
	}
	rootfsGz, err := extract("rootfs.gz")
	if err != nil {
		return fmt.Errorf("reading rootfs.gz: %w", err)
	}
	if flatkc == nil || rootfsGz == nil {
		return fmt.Errorf("flatkc or rootfs.gz not found in ext3 volume root (%d entries listed)", len(entries))
	}
	if err := os.WriteFile(filepath.Join(*outDir, "flatkc"), flatkc, 0o644); err != nil {
		return err
	}

	for _, extra := range []string{"datafs.tar.gz", "devicetree.dtb", "filechecksum", "hash_bin.sha256", "split_rootfs.tar.xz", ".db"} {
		data, err := extract(extra)
		if err != nil || data == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(*outDir, extra), data, 0o644); err != nil {
			return err
		}
	}

	fmt.Println("[4/6] rootfs.gz decryption")
	rootfsPlain, err := decryptRootfsAuto(ctx, flatkc, rootfsGz)
	if err != nil {
		return fmt.Errorf("rootfs decrypt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "rootfs.gz.dec"), rootfsPlain, 0o644); err != nil {
		return err
	}

	fmt.Println("[5/6] unpacking rootfs tar")
	rootfsDir := filepath.Join(*outDir, "rootfs")
	if err := archive.ExtractGzipTar(rootfsPlain, rootfsDir); err != nil {
		return fmt.Errorf("rootfs untar: %w", err)
	}

	fmt.Println("[6/6] unpacking nested tar+xz members")
	for _, member := range nestedTarXZMembers {
		memberPath := filepath.Join(rootfsDir, member)
		data, err := os.ReadFile(memberPath)
		if err != nil {
			continue // not every build ships every member
		}
		// Each member's own tar entries are already rooted at "./<name>/...",
		// e.g. bin.tar.xz contains "./bin/acd" -- extract into rootfsDir
		// itself so it merges in place instead of double-nesting.
		if err := archive.ExtractXZTar(data, rootfsDir); err != nil {
			fmt.Printf("      [-] %s: %v\n", member, err)
			continue
		}
		fmt.Printf("      %s merged into rootfs/\n", member)
	}

	if datafsGz, err := os.ReadFile(filepath.Join(*outDir, "datafs.tar.gz")); err == nil {
		if err := archive.ExtractGzipTar(datafsGz, filepath.Join(*outDir, "datafs")); err != nil {
			fmt.Printf("      [-] datafs.tar.gz: %v\n", err)
		} else {
			fmt.Println("      datafs.tar.gz -> datafs/")
		}
	}

	initPath := filepath.Join(rootfsDir, "bin", "init")
	if st, err := os.Stat(initPath); err == nil {
		fmt.Printf("\n[+] DONE: %s (%d bytes)\n", initPath, st.Size())
	} else {
		fmt.Printf("\n[+] DONE: unpacked under %s\n", *outDir)
	}
	return nil
}
