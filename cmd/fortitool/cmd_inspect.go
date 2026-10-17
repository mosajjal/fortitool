package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/mosajjal/fortitool/internal/diskimage"
)

const (
	inspectStageInput           = "input"
	inspectStageOuterGzip       = "outer-gzip"
	inspectStageOuterZIP        = "outer-zip"
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
	vmlinuz          string
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
		flatkc: "unknown", vmlinuz: "unknown", rootfsGz: "unknown", rootfsFamily: "unknown",
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
		{"vmlinuz", r.vmlinuz},
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

Accepts .out firmware, QCOW2 disks and single-QCOW2 ZIP packages.
Runs the firmware detection pipeline in read-only mode and reports
how far the image is recognised. It does not create an output directory,
extract files, alter the input, write temporary files or display recovered
key material.

USAGE
  fortitool inspect <image.out|disk.qcow2|image.zip>

EXAMPLES
  fortitool inspect FWF_60E-v7.4.11-build2878-FORTINET.out
  fortitool inspect FMG_VM64_KVM-v7.0.16-build0710-FORTINET.out.kvm.zip
  fortitool inspect unfamiliar-image.out

OUTPUT
  Stable field: value lines report the decoded firmware identity, L1 state,
  disk and selected-volume layout, required-member sizes, rootfs crypto family
  and cipher, rootfs container, overall status and last successful stage.
  QCOW2 disks without an L1 header report l1-state: not applicable. A validated
  cleartext header retains its firmware identity. The flatkc and
  vmlinuz fields report which kernel was selected; firmware identity may remain
  unknown when no validated L1 identity is available.
  A readable but unsupported or malformed image has status: partial and a
  stable unsupported-stage value; that is a successful inspection. A complete
  report recognises the main rootfs; it does not extract or validate nested
  archives. Use decrypt --boot-only to obtain boot files for further analysis.

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
		return usagef("usage: fortitool inspect <image.out|disk.qcow2|image.zip>")
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

	image, wrapper, err := decodeFirmwareContainer(raw)
	report.outerWrapper = wrapper
	outerStage := inspectStageOuterGzip
	if wrapper == "zip" {
		outerStage = inspectStageOuterZIP
	}
	if err != nil {
		report.stop(inspectStageInput, outerStage, err)
		report.print()
		return nil
	}
	report.lastStage = outerStage
	layer, err := decodeFirmwareLayer(ctx, image)
	if err != nil {
		report.stop(outerStage, inspectStageL1, err)
		report.print()
		return nil
	}
	report.firmwareIdentity = layer.Identity
	report.l1State = layer.State
	report.lastStage = inspectStageL1

	selection, err := openVolume(layer.Image)
	if err != nil {
		report.stop(inspectStageL1, inspectStageVolume, err)
		report.print()
		return nil
	}
	report.diskLayout = selection.DiskLayout
	report.selectedVolume = formatSelectedVolume(selection.Location)
	report.lastStage = inspectStageVolume

	report.setRequiredMembers(selection.RequiredMembers)
	if err := selection.RequiredMembers.Err(); err != nil {
		report.stop(inspectStageVolume, inspectStageRequiredMembers, err)
		report.print()
		return nil
	}
	report.lastStage = inspectStageRequiredMembers

	crypto, err := decideRootfsCrypto(ctx, selection.RequiredMembers.Kernel.Data, selection.RequiredMembers.RootfsGz.Data)
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

func (r *inspectReport) setRequiredMembers(decision requiredMembersDecision) {
	r.flatkc, r.vmlinuz = "absent", "absent"
	if decision.Kernel.Name == "vmlinuz" {
		r.vmlinuz = decision.Kernel.reportValue()
	} else {
		r.flatkc = decision.Kernel.reportValue()
		if decision.Kernel.Name == "flatkc" {
			r.vmlinuz = "not checked"
		}
	}
	r.rootfsGz = decision.RootfsGz.reportValue()
}

func formatSelectedVolume(location diskimage.FilesystemLocation) string {
	switch location.Kind {
	case "mbr-partition":
		return fmt.Sprintf("partition %d (offset %d, length %d)", location.PartitionIndex, location.Offset, location.Length)
	case "raw":
		return fmt.Sprintf("raw filesystem (offset %d, length %d)", location.Offset, location.Length)
	case "fixed-offset":
		return fmt.Sprintf("fixed offset %d (length %d)", location.Offset, location.Length)
	case "scanned-offset":
		return fmt.Sprintf("scanned offset %d (length %d)", location.Offset, location.Length)
	default:
		return fmt.Sprintf("unknown volume (offset %d, length %d)", location.Offset, location.Length)
	}
}
