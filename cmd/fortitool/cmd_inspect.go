package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mosajjal/fortitool/internal/diskimage"
	"github.com/mosajjal/fortitool/internal/l1"
)

const (
	inspectStageInput           = "input"
	inspectStageOuterGzip       = "outer-gzip"
	inspectStageL1              = "l1"
	inspectStageVolume          = "volume"
	inspectStageRequiredMembers = "required-members"
	inspectStageRootfsCrypto    = "rootfs-crypto"
	inspectStageRootfsContainer = "rootfs-container"
	inspectStageComplete        = "complete"
)

type inspectReport struct {
	inputSize        string
	outerWrapper     string
	firmwareIdentity string
	l1State          string
	diskLayout       string
	selectedVolume   string
	flatkc           string
	rootfsGz         string
	rootfsFamily     string
	rootfsCipher     string
	rootfsContainer  string
	status           string
	lastStage        string
	unsupportedStage string
	reason           string
}

func newInspectReport() *inspectReport {
	return &inspectReport{
		inputSize: "unknown", outerWrapper: "unknown", firmwareIdentity: "unknown",
		l1State: "unknown", diskLayout: "unknown", selectedVolume: "unknown",
		flatkc: "unknown", rootfsGz: "unknown", rootfsFamily: "unknown",
		rootfsCipher: "unknown", rootfsContainer: "unknown", status: "partial",
		lastStage: "none", unsupportedStage: inspectStageInput, reason: "inspection did not start",
	}
}

func (r *inspectReport) stop(last, unsupported string, err error) {
	r.status = "partial"
	r.lastStage = last
	r.unsupportedStage = unsupported
	r.reason = err.Error()
}

func (r *inspectReport) complete() {
	r.status = "complete"
	r.lastStage = inspectStageComplete
	r.unsupportedStage = "none"
	r.reason = "none"
}

func (r *inspectReport) print() {
	fields := [][2]string{
		{"input-size", r.inputSize},
		{"outer-wrapper", r.outerWrapper},
		{"firmware-identity", r.firmwareIdentity},
		{"l1-state", r.l1State},
		{"disk-layout", r.diskLayout},
		{"selected-volume", r.selectedVolume},
		{"flatkc", r.flatkc},
		{"rootfs.gz", r.rootfsGz},
		{"rootfs-key-family", r.rootfsFamily},
		{"rootfs-body-cipher", r.rootfsCipher},
		{"rootfs-container", r.rootfsContainer},
		{"status", r.status},
		{"last-successful-stage", r.lastStage},
		{"unsupported-stage", r.unsupportedStage},
		{"reason", r.reason},
	}
	for _, field := range fields {
		fmt.Printf("%s: %s\n", field[0], terminalTextLimit(field[1], 512))
	}
}

func cmdInspect(ctx context.Context, args []string) error {
	fs := newCommandFlagSet("inspect", nil)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fortitool inspect -- describe a firmware image without extracting it

Runs the existing firmware detection pipeline in read-only mode and reports
how far the image is recognised. It does not create an output directory,
extract files, alter the input, write temporary files or display recovered
key material.

USAGE
  fortitool inspect <image.out>

EXAMPLES
  fortitool inspect FWF_60E-v7.4.11-build2878-FORTINET.out
  fortitool inspect unfamiliar-image.out

OUTPUT
  Stable field: value lines report the decoded firmware identity, L1 state,
  disk and selected-volume layout, required-member sizes, rootfs crypto family
  and cipher, rootfs container, overall status and last successful stage.
  A readable but unsupported or malformed image has status: partial and a
  stable unsupported-stage value; that is a successful inspection.

EXIT CODES
  0  readable input was described, including status: partial
  1  input is absent, unreadable or otherwise inaccessible
  2  invalid flags or wrong number of positional arguments
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usage(err)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return usagef("usage: fortitool inspect <image.out>")
	}

	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return errors.New("input file does not exist")
		case errors.Is(err, os.ErrPermission):
			return errors.New("input file is not readable")
		default:
			return errors.New("input file is inaccessible")
		}
	}
	report := newInspectReport()
	report.inputSize = fmt.Sprintf("%d bytes", len(raw))
	report.lastStage = inspectStageInput

	image, wasGzip, err := decodeOuter(raw)
	if err != nil {
		report.stop(inspectStageInput, inspectStageOuterGzip, err)
		report.print()
		return nil
	}
	if wasGzip {
		report.outerWrapper = "gzip"
	} else {
		report.outerWrapper = "none"
	}
	report.lastStage = inspectStageOuterGzip

	plain, _, wasEncrypted, ok := l1.DecryptAuto(ctx, image)
	if !ok {
		report.stop(inspectStageOuterGzip, inspectStageL1, errors.New("no valid L1 header or key found"))
		report.print()
		return nil
	}
	header, ok := l1.FindHeader(plain)
	if !ok {
		report.stop(inspectStageOuterGzip, inspectStageL1, errors.New("decoded image has no validated L1 header"))
		report.print()
		return nil
	}
	report.firmwareIdentity = header.Identity
	if wasEncrypted {
		report.l1State = "encrypted"
	} else {
		report.l1State = "cleartext"
	}
	report.lastStage = inspectStageL1

	selection, err := locateVolume(plain)
	if err != nil {
		report.stop(inspectStageL1, inspectStageVolume, err)
		report.print()
		return nil
	}
	report.diskLayout = selection.DiskLayout
	report.selectedVolume = formatSelectedVolume(selection.Location)
	report.lastStage = inspectStageVolume

	flatkc, flatkcState, flatkcErr := inspectRequiredMember(selection.Volume, "flatkc")
	rootfsGz, rootfsState, rootfsErr := inspectRequiredMember(selection.Volume, "rootfs.gz")
	report.flatkc = flatkcState
	report.rootfsGz = rootfsState
	if flatkcErr != nil || rootfsErr != nil {
		if flatkcErr != nil {
			err = flatkcErr
		} else {
			err = rootfsErr
		}
		report.stop(inspectStageVolume, inspectStageRequiredMembers, err)
		report.print()
		return nil
	}
	var missing []string
	if flatkc == nil {
		missing = append(missing, "flatkc")
	}
	if rootfsGz == nil {
		missing = append(missing, "rootfs.gz")
	}
	if len(missing) != 0 {
		report.stop(inspectStageVolume, inspectStageRequiredMembers,
			fmt.Errorf("required member absent: %s", strings.Join(missing, ", ")))
		report.print()
		return nil
	}
	report.lastStage = inspectStageRequiredMembers

	crypto, err := decideRootfsCrypto(ctx, flatkc, rootfsGz)
	if err != nil {
		report.stop(inspectStageRequiredMembers, inspectStageRootfsCrypto, err)
		report.print()
		return nil
	}
	report.setRootfsCrypto(crypto)
	report.lastStage = inspectStageRootfsCrypto

	container, err := classifyRootfsPayload(crypto.Plaintext)
	if err != nil {
		report.stop(inspectStageRootfsCrypto, inspectStageRootfsContainer, err)
		report.print()
		return nil
	}
	report.rootfsContainer = container.Kind
	report.complete()
	report.print()
	return nil
}

func (r *inspectReport) setRootfsCrypto(decision *rootfsDecision) {
	r.rootfsFamily = decision.Family
	r.rootfsCipher = decision.Cipher
}

func inspectRequiredMember(volume *diskimage.FS, name string) ([]byte, string, error) {
	data, err := volume.ReadFile(name)
	if errors.Is(err, diskimage.ErrNotFound) {
		return nil, "absent", nil
	}
	if err != nil {
		return nil, "unreadable", fmt.Errorf("reading required member %s: %w", name, err)
	}
	return data, fmt.Sprintf("present (%d bytes)", len(data)), nil
}

func formatSelectedVolume(location diskimage.FilesystemLocation) string {
	switch location.Kind {
	case "mbr-partition":
		return fmt.Sprintf("partition %d (offset %d, length %d)", location.PartitionIndex, location.Offset, location.Length)
	case "raw":
		return fmt.Sprintf("raw filesystem (offset %d, length %d)", location.Offset, location.Length)
	case "fixed-offset":
		return fmt.Sprintf("fixed offset %d (length %d)", location.Offset, location.Length)
	default:
		return fmt.Sprintf("scanned offset %d (length %d)", location.Offset, location.Length)
	}
}
