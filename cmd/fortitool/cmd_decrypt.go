package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mosajjal/fortitool/internal/archive"
	"github.com/mosajjal/fortitool/internal/diskimage"
	"github.com/mosajjal/fortitool/internal/l1"
	"github.com/mosajjal/fortitool/internal/qcow2"
)

// nestedTarXZMembers are the tar+xz archives FortiOS nests inside the outer
// rootfs tar; each is extracted into its own subdirectory named after it.
var nestedTarXZMembers = []string{"bin.tar.xz", "usr.tar.xz", "migadmin.tar.xz", "node-scripts.tar.xz"}

func cmdDecrypt(ctx context.Context, args []string) error {
	fs := newCommandFlagSet("decrypt", nil)
	outDir := fs.String("o", "", "output directory (required)")
	showKeys := fs.Bool("show-keys", false, "print recovered key material")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fortitool decrypt -- full pipeline: raw .out -> unpacked rootfs, one command

Runs the whole chain in order, auto-detecting the crypto era at each
layer (no version/model/architecture flag needed):
  1. gunzip the outer .out wrapper
  2. L1 XOR decrypt (known-plaintext attack, or detect already-cleartext)
  3. locate the FORTIOS volume -- appliance images (MBR + ext3 @512),
     VM/KVM images (qcow2 disk with partitioned ext filesystems), and
     fixed-offset layouts (e.g. FortiManager @0x400000) are all handled,
     pure Go, no mount/debugfs/7z
  4. locate flatkc + rootfs.gz, extract datafs.tar.gz/devicetree.dtb/etc
     alongside them if present
  5. decrypt rootfs.gz (any known FortiOS 7.4.x-8.0 scheme)
  6. unpack the rootfs payload -- gzip tar (<=7.6) or xz-compressed ext4
     filesystem image (8.0 VM) -- then merge in any nested bin.tar.xz/
     usr.tar.xz/migadmin.tar.xz/node-scripts.tar.xz members, then unpack
     datafs.tar.gz if present

USAGE
  fortitool decrypt -o OUTDIR <image.out>

FLAGS
  -o OUTDIR     output directory (required) -- must not already exist;
                published only on success, private to the invoking identity
                (mode 0700 on Unix; protected per-user DACL on Windows)
  --show-keys   print recovered key material (redacted by default)

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
  2  invalid flags, missing -o, or wrong number of positional arguments
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usage(err)
	}
	if fs.NArg() != 1 || *outDir == "" {
		fs.Usage()
		return usagef("usage: fortitool decrypt -o OUTDIR <image.out>")
	}
	inPath := fs.Arg(0)
	staged, err := newStagedOutputDir(*outDir)
	if err != nil {
		return err
	}
	defer staged.Cleanup()

	fmt.Printf("[1/6] loading %s\n", terminalText(inPath))
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
		fmt.Printf("      %s\n", formatRecoveredKey(key, *showKeys))
	} else {
		fmt.Println("      already cleartext")
	}

	fmt.Println("[3/6] locating the FORTIOS volume")
	volume, layout, err := openVolume(plain)
	if err != nil {
		return fmt.Errorf("volume discovery: %w", err)
	}
	fmt.Printf("      layout: %s\n", terminalText(layout))

	extract := func(name string) ([]byte, error) {
		data, err := volume.ReadFile(name)
		if errors.Is(err, diskimage.ErrNotFound) {
			return nil, nil // absent -- not every image carries every optional file
		}
		return data, err
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
		return fmt.Errorf("flatkc or rootfs.gz not found in the located volume")
	}
	if err := os.WriteFile(filepath.Join(staged.temp, "flatkc"), flatkc, 0o644); err != nil {
		return err
	}

	for _, extra := range []string{"datafs.tar.gz", "devicetree.dtb", "filechecksum", "hash_bin.sha256", "split_rootfs.tar.xz", ".db"} {
		data, err := extract(extra)
		if err != nil {
			return fmt.Errorf("reading %s: %w", extra, err)
		}
		if data == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(staged.temp, extra), data, 0o644); err != nil {
			return err
		}
	}

	fmt.Println("[4/6] rootfs.gz decryption")
	rootfsPlain, err := decryptRootfsAuto(ctx, flatkc, rootfsGz, *showKeys)
	if err != nil {
		return fmt.Errorf("rootfs decrypt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(staged.temp, "rootfs.gz.dec"), rootfsPlain, 0o644); err != nil {
		return err
	}

	fmt.Println("[5/6] unpacking rootfs payload")
	rootfsDir := filepath.Join(staged.temp, "rootfs")
	if err := extractRootfsPayload(rootfsPlain, rootfsDir); err != nil {
		return fmt.Errorf("rootfs unpack: %w", err)
	}

	fmt.Println("[6/6] unpacking nested tar+xz members")
	if err := extractNestedMembers(rootfsDir); err != nil {
		return err
	}

	if extracted, err := extractDatafs(staged.temp); err != nil {
		return err
	} else if extracted {
		fmt.Println("      datafs.tar.gz -> datafs/")
	}

	initSize := int64(-1)
	if st, err := os.Stat(filepath.Join(rootfsDir, "bin", "init")); err == nil {
		initSize = st.Size()
	}
	if err := staged.Commit(); err != nil {
		return err
	}
	if initSize >= 0 {
		fmt.Printf("\n[+] DONE: %s (%d bytes)\n", terminalText(filepath.Join(*outDir, "rootfs", "bin", "init")), initSize)
	} else {
		fmt.Printf("\n[+] DONE: unpacked under %s\n", terminalText(*outDir))
	}
	return nil
}

func extractNestedMembers(rootfsDir string) error {
	for _, member := range nestedTarXZMembers {
		memberPath := filepath.Join(rootfsDir, member)
		info, err := os.Lstat(memberPath)
		if os.IsNotExist(err) {
			continue // not every build ships every member
		}
		if err != nil {
			return fmt.Errorf("checking nested member %s: %w", member, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("nested member %s is not a regular file", member)
		}
		data, err := os.ReadFile(memberPath)
		if err != nil {
			return fmt.Errorf("reading nested member %s: %w", member, err)
		}
		// Each member's own tar entries are already rooted at "./<name>/...",
		// e.g. bin.tar.xz contains "./bin/acd" -- extract into rootfsDir
		// itself so it merges in place instead of double-nesting.
		if err := archive.ExtractXZTar(data, rootfsDir); err != nil {
			return fmt.Errorf("nested member %s: %w", member, err)
		}
		fmt.Printf("      %s merged into rootfs/\n", member)
	}

	return nil
}

func extractDatafs(outputDir string) (bool, error) {
	datafsPath := filepath.Join(outputDir, "datafs.tar.gz")
	info, err := os.Lstat(datafsPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking datafs.tar.gz: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("datafs.tar.gz is not a regular file")
	}
	datafsGz, err := os.ReadFile(datafsPath)
	if err != nil {
		return false, fmt.Errorf("reading datafs.tar.gz: %w", err)
	}
	if err := archive.ExtractGzipTar(datafsGz, filepath.Join(outputDir, "datafs")); err != nil {
		return false, fmt.Errorf("datafs.tar.gz: %w", err)
	}
	return true, nil
}

// openVolume locates a readable ext filesystem inside a decrypted firmware
// image, handling every known on-disk layout:
//
//   - qcow2 VM disks (FortiGate/FortiManager VM .out payloads): the guest
//     disk is exposed read-only via internal/qcow2, then scanned for ext
//     volumes exactly like a raw disk;
//   - raw disks with an MBR partition table (appliance images keep their
//     ext3 volume at sector 1; VM boot disks carry several partitions);
//   - fixed-offset layouts with no partition table (some FortiManager
//     images start their volume at 0x400000).
//
// When several candidate volumes exist (partitioned VM disks), the one
// actually containing flatkc + rootfs.gz wins.
func openVolume(img []byte) (*diskimage.FS, string, error) {
	var (
		fss    []*diskimage.FS
		layout string
	)
	switch {
	case qcow2.IsQCow2(img):
		rd, err := qcow2.Open(bytes.NewReader(img))
		if err != nil {
			return nil, "", fmt.Errorf("qcow2: %w", err)
		}
		fss = diskimage.FindFilesystems(rd, rd.Size())
		layout = fmt.Sprintf("qcow2 VM disk (%d MB virtual)", rd.Size()>>20)
	default:
		fss = diskimage.FindFilesystems(bytes.NewReader(img), int64(len(img)))
		layout = "raw disk"
	}
	if len(fss) == 0 {
		return nil, "", fmt.Errorf("no ext2/3/4 filesystem found in the decrypted image (tried MBR partitions, offset 512, and common fixed offsets)")
	}
	for _, vol := range fss {
		if _, err := vol.ReadFile("flatkc"); err != nil {
			continue
		}
		if _, err := vol.ReadFile("rootfs.gz"); err != nil {
			continue
		}
		return vol, layout, nil
	}
	// no volume has both files; hand back the first so the caller can
	// produce a precise error about what IS there
	return fss[0], layout, nil
}

// extractRootfsPayload unpacks a decrypted rootfs body. Two container
// shapes exist across the product line:
//
//   - gzip-compressed GNU tar (everything through 7.6.x): extracted as a
//     plain tar;
//   - xz-compressed ext4 filesystem image (8.0 VM builds): decompressed,
//     then dumped file-by-file through the pure-Go ext reader.
func extractRootfsPayload(plain []byte, destDir string) error {
	switch {
	case len(plain) >= 2 && plain[0] == 0x1f && plain[1] == 0x8b:
		return archive.ExtractGzipTar(plain, destDir)
	case len(plain) >= 6 && bytes.Equal(plain[:6], []byte("\xfd7zXZ\x00")):
		raw, err := archive.XZDecompress(plain)
		if err != nil {
			return fmt.Errorf("xz decompress: %w", err)
		}
		vol, err := diskimage.Open(raw)
		if err != nil {
			return fmt.Errorf("decompressed payload is not an ext filesystem: %w", err)
		}
		return vol.ExtractAll(destDir)
	default:
		prefix := plain
		if len(prefix) > 6 {
			prefix = prefix[:6]
		}
		return fmt.Errorf("decrypted rootfs is neither gzip nor xz (starts %x)", prefix)
	}
}
