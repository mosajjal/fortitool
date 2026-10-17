package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mosajjal/fortitool/internal/archive"
	"github.com/mosajjal/fortitool/internal/diskimage"
	"github.com/mosajjal/fortitool/internal/qcow2"
)

// nestedTarXZMembers are the tar+xz archives FortiOS nests inside the outer
// rootfs tar. FortiGate images merge them into the base rootfs.
var nestedTarXZMembers = []string{"bin.tar.xz", "usr.tar.xz", "migadmin.tar.xz", "node-scripts.tar.xz"}

func cmdDecrypt(ctx context.Context, args []string) error {
	fs := newCommandFlagSet("decrypt", nil)
	outDir := fs.String("o", "", "output directory (required)")
	showKeys := fs.Bool("show-keys", false, "print recovered key material")
	bootOnly := fs.Bool("boot-only", false, "extract the boot filesystem without decoding rootfs")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fortitool decrypt -- extract FortiOS firmware or FAZ/FMG KVM installation disks

Accepts raw .out firmware, bare QCOW2 disks, and ZIP packages containing
exactly one regular QCOW2 file (at most 2 GiB expanded). Formats are detected
from their contents; no version, model or architecture flag is needed.

The full pipeline unwraps gzip or ZIP, validates L1 for non-QCOW2 input,
finds the boot filesystem and its flatkc or vmlinuz kernel plus rootfs.gz, decrypts
supported rootfs schemes, and extracts gzip tar/CPIO or XZ CPIO/ext payloads.

FortiGate nested archives are merged into rootfs/. For vmlinuz boot layouts
(FAZ/FMG), nested and additional boot archives are extracted as separate
layers: the bootstrap and application archives can have different files at
the same path. Originals are retained; no boot-time overlay order is assumed.

USAGE
  fortitool decrypt [--boot-only] -o OUTDIR <image.out|disk.qcow2|image.zip>

FLAGS
  -o OUTDIR     required; must not exist. Output is published only on success,
                private to the invoking identity (0700 on Unix; protected
                per-user DACL on Windows).
  --boot-only   extract readable directories, regular files and symlinks from
                the selected boot filesystem. Unreadable entries and special
                files (such as device/FIFO nodes) are skipped; success does not
                certify a complete copy. Rootfs and additional archives stay
                encoded. Use 'unpack' on readable additional archives.
  --show-keys   print recovered key material (redacted by default)

EXAMPLES
  fortitool decrypt -o work/v7411 FWF_60E-v7.4.11-build2878-FORTINET.out
  fortitool decrypt -o work/fmg FMG_VM64_KVM-v7.0.16-build0710-FORTINET.out.kvm.zip
  fortitool decrypt --boot-only -o work/boot faz.qcow2
  fortitool unpack -o work/extensions work/boot/rootfs-ext.tar.xz

OUTPUT LAYOUT (full pipeline)
  flatkc or vmlinuz, rootfs.gz.dec, ...    kernel, decoded rootfs and extras
  rootfs/                                base root filesystem
  datafs/                                unpacked datafs.tar.gz, if present
  layers/rootfs/<archive-name>/           FAZ/FMG nested archives, if present
  layers/boot/<archive-name>/             FAZ/FMG boot archives, if present

For example, the base rootfs/bin/init and the application file
layers/rootfs/bin.tar.xz/bin/init are both retained. Layers are for static
analysis, not a reconstructed bootable filesystem.

FAZ/FMG support includes plain gzip/XZ CPIO and protected x86-64 vmlinuz
with AES-128-CTR rootfs. See the README for the tested KVM builds. Upgrade
.out packages and hardware-appliance images need separate validation.

EXIT CODES
  0  requested full pipeline or explicit boot-only extraction succeeded
  1  failed; no output directory is published
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
		return usagef("usage: fortitool decrypt [--boot-only] -o OUTDIR <image>")
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
	img, _, err := decodeFirmwareContainer(raw)
	if err != nil {
		return fmt.Errorf("outer container: %w", err)
	}
	fmt.Printf("      %d bytes\n", len(img))

	fmt.Println("[2/6] L1 outer-layer decryption")
	layer, err := decodeFirmwareLayer(ctx, img)
	if err != nil {
		return err
	}
	if layer.State == "encrypted" {
		fmt.Printf("      %s\n", formatRecoveredKey(layer.Key, *showKeys))
	} else {
		fmt.Printf("      %s\n", layer.State)
	}

	fmt.Println("[3/6] locating the firmware boot volume")
	selection, err := openVolume(layer.Image)
	if err != nil {
		return fmt.Errorf("volume discovery: %w", err)
	}
	fmt.Printf("      layout: %s\n", terminalText(selection.description))
	if err := selection.RequiredMembers.Err(); err != nil {
		return err
	}
	volume := selection.Volume
	if *bootOnly {
		if err := volume.ExtractAll(staged.temp); err != nil {
			return fmt.Errorf("boot filesystem: %w", err)
		}
		if err := staged.Commit(); err != nil {
			return err
		}
		fmt.Printf("\n[+] DONE: boot files extracted under %s; rootfs was not decrypted or unpacked\n", terminalText(*outDir))
		return nil
	}
	flatkc := selection.RequiredMembers.Kernel.Data
	rootfsGz := selection.RequiredMembers.RootfsGz.Data
	if err := os.WriteFile(filepath.Join(staged.temp, selection.RequiredMembers.Kernel.Name), flatkc, 0o644); err != nil {
		return err
	}

	extras := []string{"datafs.tar.gz", "devicetree.dtb", "filechecksum", "hash_bin.sha256", "split_rootfs.tar.xz", ".db"}
	layered := selection.RequiredMembers.Kernel.Name == "vmlinuz"
	if layered {
		extras = append(extras, bootArchiveMembers...)
	}
	for _, extra := range extras {
		data, err := readOptionalMember(volume, extra)
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
	if layered {
		if err := extractArchiveLayers(rootfsDir, filepath.Join(staged.temp, "layers", "rootfs"), append([]string{"lib.tar.xz"}, nestedTarXZMembers...)); err != nil {
			return err
		}
		if err := extractArchiveLayers(staged.temp, filepath.Join(staged.temp, "layers", "boot"), bootArchiveMembers); err != nil {
			return err
		}
	} else {
		if err := extractNestedMembers(rootfsDir); err != nil {
			return err
		}
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
	if initSize >= 0 && !layered {
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
//   - qcow2 VM disks: the guest
//     disk is exposed read-only via internal/qcow2, then scanned for ext
//     volumes exactly like a raw disk;
//   - raw disks with an MBR partition table (appliance images keep their
//     ext3 volume at sector 1; VM boot disks carry several partitions);
//   - fixed-offset layouts with no partition table.
//
// When several candidate volumes exist (partitioned VM disks), the one
// actually containing a kernel (flatkc or vmlinuz) and rootfs.gz wins.
type volumeSelection struct {
	Volume          *diskimage.FS
	DiskLayout      string
	Location        diskimage.FilesystemLocation
	RequiredMembers requiredMembersDecision
	description     string
}

type volumeFileReader interface {
	ReadFile(string) ([]byte, error)
}

type memberDecision struct {
	Name string
	Data []byte
	Err  error
}

type requiredMembersDecision struct {
	Kernel   memberDecision
	RootfsGz memberDecision
}

func readRequiredMembers(volume volumeFileReader) requiredMembersDecision {
	kernel := readMember(volume, "flatkc")
	if errors.Is(kernel.Err, diskimage.ErrNotFound) {
		kernel = readMember(volume, "vmlinuz")
		if errors.Is(kernel.Err, diskimage.ErrNotFound) {
			kernel.Name = "flatkc or vmlinuz"
		}
	}
	return requiredMembersDecision{Kernel: kernel, RootfsGz: readMember(volume, "rootfs.gz")}
}

func readMember(volume volumeFileReader, name string) memberDecision {
	data, err := volume.ReadFile(name)
	return memberDecision{Name: name, Data: data, Err: err}
}

func (d requiredMembersDecision) Err() error {
	var missing []string
	for _, member := range []memberDecision{d.Kernel, d.RootfsGz} {
		switch {
		case member.Err == nil:
		case errors.Is(member.Err, diskimage.ErrNotFound):
			missing = append(missing, member.Name)
		default:
			return fmt.Errorf("reading required member %s: %w", member.Name, member.Err)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("required member absent: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (m memberDecision) reportValue() string {
	switch {
	case m.Err == nil:
		return fmt.Sprintf("present (%d bytes)", len(m.Data))
	case errors.Is(m.Err, diskimage.ErrNotFound):
		return "absent"
	default:
		return "unreadable"
	}
}

func readOptionalMember(volume volumeFileReader, name string) ([]byte, error) {
	member := readMember(volume, name)
	if errors.Is(member.Err, diskimage.ErrNotFound) {
		return nil, nil
	}
	return member.Data, member.Err
}

func openVolume(img []byte) (*volumeSelection, error) {
	return locateVolume(img)
}

func locateVolume(img []byte) (*volumeSelection, error) {
	var (
		volumes     []diskimage.LocatedFilesystem
		diskLayout  string
		description string
	)
	switch {
	case qcow2.IsQCow2(img):
		rd, err := qcow2.Open(bytes.NewReader(img))
		if err != nil {
			return nil, fmt.Errorf("qcow2: %w", err)
		}
		volumes = diskimage.FindFilesystemVolumes(rd, rd.Size())
		diskLayout = "qcow2"
		description = fmt.Sprintf("qcow2 VM disk (%d MB virtual)", rd.Size()>>20)
	default:
		volumes = diskimage.FindFilesystemVolumes(bytes.NewReader(img), int64(len(img)))
		description = "raw disk"
	}
	if len(volumes) == 0 {
		return nil, fmt.Errorf("no ext2/3/4 filesystem found in the decrypted image (tried MBR partitions, offset 512, and common fixed offsets)")
	}
	selectVolume := func(located diskimage.LocatedFilesystem) *volumeSelection {
		return &volumeSelection{
			Volume: located.FS, DiskLayout: diskLayoutForLocation(diskLayout, located.Location),
			Location: located.Location, RequiredMembers: readRequiredMembers(located.FS), description: description,
		}
	}
	var first *volumeSelection
	for _, located := range volumes {
		selection := selectVolume(located)
		if first == nil {
			first = selection
		}
		if selection.RequiredMembers.Err() == nil {
			return selection, nil
		}
	}
	// no volume has both files; hand back the first so the caller can
	// produce a precise error about what IS there
	return first, nil
}

func diskLayoutForLocation(containerLayout string, location diskimage.FilesystemLocation) string {
	if containerLayout != "" {
		return containerLayout
	}
	switch location.Kind {
	case "mbr-partition":
		return "partitioned"
	case "raw":
		return "raw"
	case "fixed-offset", "scanned-offset":
		return location.Kind
	default:
		return "unknown"
	}
}

// extractRootfsPayload unpacks a decrypted rootfs body:
//
//   - gzip-compressed GNU tar or newc CPIO: classified from the decompressed
//     stream and extracted directly. Skips classifyRootfsPayload, which would
//     inflate the whole archive once more just to learn the container kind;
//   - XZ-compressed newc CPIO or ext filesystem: decompressed, classified,
//     and extracted through the existing archive or filesystem reader.
func extractRootfsPayload(plain []byte, destDir string) error {
	if len(plain) >= 2 && plain[0] == 0x1f && plain[1] == 0x8b {
		return archive.ExtractGzipRootfs(plain, destDir)
	}
	decision, err := classifyRootfsPayload(plain)
	if err != nil {
		return err
	}
	switch decision.Kind {
	case "xz/ext":
		return decision.ext.ExtractAll(destDir)
	case "xz/newc":
		return archive.ExtractNewc(bytes.NewReader(decision.newc), destDir)
	default:
		return fmt.Errorf("unsupported rootfs payload kind %q", decision.Kind)
	}
}

type rootfsPayloadDecision struct {
	Kind string
	ext  *diskimage.FS
	newc []byte
}

func classifyRootfsPayload(plain []byte) (*rootfsPayloadDecision, error) {
	switch {
	case len(plain) >= 2 && plain[0] == 0x1f && plain[1] == 0x8b:
		format, err := archive.ClassifyGzipRootfs(plain)
		if err != nil {
			return nil, err
		}
		return &rootfsPayloadDecision{Kind: "gzip/" + string(format)}, nil
	case len(plain) >= 6 && bytes.Equal(plain[:6], []byte("\xfd7zXZ\x00")):
		raw, err := archive.XZDecompress(plain)
		if err != nil {
			return nil, fmt.Errorf("xz decompress: %w", err)
		}
		if bytes.HasPrefix(raw, []byte("070701")) || bytes.HasPrefix(raw, []byte("070702")) {
			if err := archive.ValidateNewc(bytes.NewReader(raw)); err != nil {
				return nil, err
			}
			return &rootfsPayloadDecision{Kind: "xz/newc", newc: raw}, nil
		}
		vol, err := diskimage.Open(raw)
		if err != nil {
			return nil, fmt.Errorf("decompressed payload is not an ext filesystem: %w", err)
		}
		return &rootfsPayloadDecision{Kind: "xz/ext", ext: vol}, nil
	default:
		prefix := plain
		if len(prefix) > 6 {
			prefix = prefix[:6]
		}
		return nil, fmt.Errorf("decrypted rootfs is neither gzip nor xz (starts %x)", prefix)
	}
}
