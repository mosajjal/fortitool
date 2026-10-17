package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/mosajjal/fortitool/internal/diskimage"
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/chacha20"
)

func TestCmdInspectCompleteReadOnlyReport(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "firmware.out")
	rootfs := syntheticNewcRootfs(t, true)
	image := syntheticDecryptImage(t, rootfs)
	if err := os.WriteFile(input, image, 0o600); err != nil {
		t.Fatal(err)
	}
	before := directoryNames(t, dir)

	out, err := captureStdout(t, func() error {
		return cmdInspect(context.Background(), []string{input})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"input-size: ",
		"outer-wrapper: gzip\n",
		"firmware-identity: SYNTH-v0.0.0-FW-build0000-test\n",
		"l1-state: cleartext\n",
		"disk-layout: raw\n",
		"selected-volume: raw filesystem (offset 0, length 10240)\n",
		"flatkc: present (16 bytes)\n",
		"rootfs.gz: present (" + strconv.Itoa(len(rootfs)) + " bytes)\n",
		"rootfs-key-family: none\n",
		"rootfs-body-cipher: none\n",
		"rootfs-container: gzip/newc\n",
		"status: complete\n",
		"last-successful-stage: complete\n",
		"unsupported-stage: none\n",
		"reason: none\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output does not contain %q:\n%s", want, out)
		}
	}
	after := directoryNames(t, dir)
	if !slices.Equal(before, after) {
		t.Fatalf("inspect left residue: before=%v after=%v", before, after)
	}
}

func TestCmdInspectReadablePartialStagesExitSuccessfully(t *testing.T) {
	tests := []struct {
		name            string
		image           func(*testing.T) []byte
		wantLast        string
		wantUnsupported string
		wantReason      string
	}{
		{
			name: "corrupt outer gzip",
			image: func(t *testing.T) []byte {
				data := gzipBytes(t, []byte("decoded firmware"))
				return data[:len(data)-4]
			},
			wantLast: inspectStageInput, wantUnsupported: inspectStageOuterGzip,
			wantReason: "gunzip:",
		},
		{
			name:     "empty",
			image:    func(*testing.T) []byte { return nil },
			wantLast: inspectStageOuterGzip, wantUnsupported: inspectStageL1,
			wantReason: "no valid L1 header or key found",
		},
		{
			name: "missing required member",
			image: func(t *testing.T) []byte {
				plain, err := gunzipOuter(syntheticDecryptImage(t, syntheticNewcRootfs(t, true)))
				if err != nil {
					t.Fatal(err)
				}
				plain = bytes.Replace(plain, []byte("rootfs.gz"), []byte("missing.x"), 1)
				return gzipBytes(t, plain)
			},
			wantLast: inspectStageVolume, wantUnsupported: inspectStageRequiredMembers,
			wantReason: "required member absent: rootfs.gz",
		},
		{
			name: "unsupported CRC newc",
			image: func(t *testing.T) []byte {
				rootfs := rewriteGzipPrefix(t, syntheticNewcRootfs(t, true), []byte("070702"))
				return syntheticDecryptImage(t, rootfs)
			},
			wantLast: inspectStageRootfsCrypto, wantUnsupported: inspectStageRootfsContainer,
			wantReason: "CRC-form 070702 is not supported",
		},
		{
			name: "invalid tar",
			image: func(t *testing.T) []byte {
				return syntheticDecryptImage(t, gzipBytes(t, []byte("not a tar archive")))
			},
			wantLast: inspectStageRootfsCrypto, wantUnsupported: inspectStageRootfsContainer,
			wantReason: "tar:",
		},
		{
			name: "unsupported rootfs crypto",
			image: func(t *testing.T) []byte {
				return syntheticDecryptImage(t, []byte("unsupported rootfs crypto"))
			},
			wantLast: inspectStageRequiredMembers, wantUnsupported: inspectStageRootfsCrypto,
			wantReason: "extracting kernel payload from flatkc",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join(t.TempDir(), "input.out")
			if err := os.WriteFile(input, tc.image(t), 0o600); err != nil {
				t.Fatal(err)
			}
			tempDir := t.TempDir()
			workingDir := t.TempDir()
			result := runCLISubprocessAt(t, []string{"inspect", input}, "", workingDir, []string{"TMPDIR=" + tempDir})
			if result.code != 0 {
				t.Fatalf("exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
			}
			for _, want := range []string{
				"status: partial\n",
				"last-successful-stage: " + tc.wantLast + "\n",
				"unsupported-stage: " + tc.wantUnsupported + "\n",
				tc.wantReason,
			} {
				if !strings.Contains(result.stdout, want) {
					t.Fatalf("stdout does not contain %q:\n%s", want, result.stdout)
				}
			}
			assertEmptyDirectory(t, tempDir)
			assertEmptyDirectory(t, workingDir)
		})
	}
}

func TestCmdInspectEncryptedL1NeverPrintsKeyMaterial(t *testing.T) {
	const key = "KnownInspectKey0123456789ABCDEFG"
	dir := t.TempDir()
	input := filepath.Join(dir, "encrypted.out")
	clear, err := gunzipOuter(syntheticDecryptImage(t, syntheticNewcRootfs(t, true)))
	if err != nil {
		t.Fatal(err)
	}
	encrypted := encryptSyntheticL1(clear, []byte(key))
	if err := os.WriteFile(input, gzipBytes(t, encrypted), 0o600); err != nil {
		t.Fatal(err)
	}
	before := directoryNames(t, dir)

	tempDir := t.TempDir()
	workingDir := t.TempDir()
	result := runCLISubprocessAt(t, []string{"inspect", input}, "", workingDir, []string{"TMPDIR=" + tempDir})
	if result.code != 0 {
		t.Fatalf("exit = %d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	if !strings.Contains(result.stdout, "l1-state: encrypted\n") || !strings.Contains(result.stdout, "status: complete\n") {
		t.Fatalf("encrypted L1 was not completely inspected:\n%s", result.stdout)
	}
	if strings.Contains(result.stdout, key) || strings.Contains(result.stderr, key) {
		t.Fatalf("key material was printed:\nstdout:\n%s\nstderr:\n%s", result.stdout, result.stderr)
	}
	after := directoryNames(t, dir)
	if !slices.Equal(before, after) {
		t.Fatalf("inspect left residue: before=%v after=%v", before, after)
	}
	assertEmptyDirectory(t, tempDir)
	assertEmptyDirectory(t, workingDir)
}

func TestCmdInspectRecognisedRootfsCrypto(t *testing.T) {
	state := make([]byte, 48)
	for i := range state {
		state[i] = byte(i + 1)
	}
	kernel := make([]byte, 1_000_001)
	copy(kernel[260:], state)
	flatkc := gzipBytes(t, kernel)

	var tarData bytes.Buffer
	tw := tar.NewWriter(&tarData)
	payload := []byte("synthetic encrypted rootfs")
	if err := tw.WriteHeader(&tar.Header{Name: "rootfs/control", Mode: 0o600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	plainRootfs := gzipBytes(t, tarData.Bytes())
	cipher, err := chacha20.NewUnauthenticatedCipher(state[:32], state[36:])
	if err != nil {
		t.Fatal(err)
	}
	cipher.SetCounter(binary.LittleEndian.Uint32(state[32:36]))
	encryptedRootfs := make([]byte, len(plainRootfs))
	cipher.XORKeyStream(encryptedRootfs, plainRootfs)
	encryptedRootfs = append(encryptedRootfs, bytes.Repeat([]byte{0x5a}, 256)...)

	input := filepath.Join(t.TempDir(), "encrypted-rootfs.out")
	if err := os.WriteFile(input, syntheticDecryptImageWithMembers(t, flatkc, encryptedRootfs), 0o600); err != nil {
		t.Fatal(err)
	}
	result := runCLISubprocess(t, []string{"inspect", input}, "")
	if result.code != 0 {
		t.Fatalf("exit = %d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	for _, want := range []string{
		"rootfs-key-family: chacha20-static\n",
		"rootfs-body-cipher: chacha20\n",
		"rootfs-container: gzip/tar\n",
		"status: complete\n",
	} {
		if !strings.Contains(result.stdout, want) {
			t.Fatalf("stdout does not contain %q:\n%s", want, result.stdout)
		}
	}
	if strings.Contains(result.stdout+result.stderr, terminalText(string(state))) {
		t.Fatalf("rootfs state was printed:\nstdout:\n%s\nstderr:\n%s", result.stdout, result.stderr)
	}
}

func TestInspectRejectsKeyFlagAndHidesInaccessiblePath(t *testing.T) {
	for _, args := range [][]string{
		{"inspect", "--show-keys", "image.out"},
		{"inspect", "image.out", "--show-keys"},
	} {
		result := runCLISubprocess(t, args, "")
		if result.code != 2 {
			t.Fatalf("args %v exit = %d, want 2", args, result.code)
		}
	}

	privatePath := filepath.Join(t.TempDir(), "private\x1bname")
	result := runCLISubprocess(t, []string{"inspect", privatePath}, "")
	if result.code != 1 {
		t.Fatalf("exit = %d, want 1", result.code)
	}
	if strings.Contains(result.stdout+result.stderr, privatePath) || strings.Contains(result.stdout+result.stderr, "\x1b") {
		t.Fatalf("private/control path was exposed:\n%s%s", result.stdout, result.stderr)
	}
	wantError := "input file does not exist"
	if runtime.GOOS == "windows" {
		wantError = "input file is inaccessible"
	}
	if !strings.Contains(result.stderr, wantError) {
		t.Fatalf("stderr = %q", result.stderr)
	}

	directoryResult := runCLISubprocess(t, []string{"inspect", t.TempDir()}, "")
	if directoryResult.code != 1 || !strings.Contains(directoryResult.stderr, "input file is inaccessible") {
		t.Fatalf("directory input result = %+v", directoryResult)
	}
}

func TestInspectAndDecryptConsumeSharedDecisions(t *testing.T) {
	rootfs := syntheticNewcRootfs(t, true)
	image, err := gunzipOuter(syntheticDecryptImage(t, rootfs))
	if err != nil {
		t.Fatal(err)
	}
	selection, err := openVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := selection.RequiredMembers.Err(); err != nil {
		t.Fatal(err)
	}
	report := newInspectReport()
	report.setRequiredMembers(selection.RequiredMembers)
	if report.flatkc != "present (16 bytes)" || report.rootfsGz != "present ("+strconv.Itoa(len(rootfs))+" bytes)" {
		t.Fatalf("formatted members = %q/%q", report.flatkc, report.rootfsGz)
	}
	decision, err := decideRootfsCrypto(context.Background(), selection.RequiredMembers.Flatkc.Data, selection.RequiredMembers.RootfsGz.Data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := captureStdout(t, func() error {
		got, err := decryptRootfsAuto(context.Background(), selection.RequiredMembers.Flatkc.Data, selection.RequiredMembers.RootfsGz.Data, false)
		if err == nil && !bytes.Equal(got, decision.Plaintext) {
			t.Fatal("decrypt and inspect rootfs plaintext decisions differ")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(decrypted, "already plain gzip") {
		t.Fatalf("decrypt output does not reflect shared plain decision: %s", decrypted)
	}
	container, err := classifyRootfsPayload(decision.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if container.Kind != "gzip/newc" {
		t.Fatalf("container = %q", container.Kind)
	}
	dest := filepath.Join(t.TempDir(), "rootfs")
	if err := extractRootfsPayload(decision.Plaintext, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "bin", "init")); err != nil {
		t.Fatal(err)
	}
}

func TestRequiredMembersDecisionSharedPresenceMissingAndErrors(t *testing.T) {
	readFailure := errors.New("synthetic member read failure")
	tests := []struct {
		name       string
		volume     stubVolume
		wantFlatkc string
		wantRootfs string
		wantErr    string
	}{
		{
			name: "present",
			volume: stubVolume{
				"flatkc":    {data: []byte("kernel")},
				"rootfs.gz": {data: []byte("rootfs")},
			},
			wantFlatkc: "present (6 bytes)", wantRootfs: "present (6 bytes)",
		},
		{
			name: "missing",
			volume: stubVolume{
				"flatkc":    {data: []byte("kernel")},
				"rootfs.gz": {err: diskimage.ErrNotFound},
			},
			wantFlatkc: "present (6 bytes)", wantRootfs: "absent",
			wantErr: "required member absent: rootfs.gz",
		},
		{
			name: "error",
			volume: stubVolume{
				"flatkc":    {err: readFailure},
				"rootfs.gz": {data: []byte("rootfs")},
			},
			wantFlatkc: "unreadable", wantRootfs: "present (6 bytes)",
			wantErr: "reading required member flatkc: synthetic member read failure",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision := readRequiredMembers(tc.volume)
			report := newInspectReport()
			report.setRequiredMembers(decision)
			if report.flatkc != tc.wantFlatkc || report.rootfsGz != tc.wantRootfs {
				t.Fatalf("formatted members = %q/%q, want %q/%q", report.flatkc, report.rootfsGz, tc.wantFlatkc, tc.wantRootfs)
			}
			err := decision.Err()
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestScannedOffsetReportingPreservesDiscoveryKind(t *testing.T) {
	location := diskimage.FilesystemLocation{
		Kind: "scanned-offset", Offset: 0x800000, Length: 0x300000,
	}
	if got := diskLayoutForLocation("", location); got != "scanned-offset" {
		t.Fatalf("disk layout = %q, want scanned-offset", got)
	}
	if got := formatSelectedVolume(location); got != "scanned offset 8388608 (length 3145728)" {
		t.Fatalf("selected volume = %q", got)
	}
}

func TestCmdInspectReportsDiscoveredVolumeMetadata(t *testing.T) {
	ext, err := gunzipOuter(syntheticDecryptImage(t, syntheticNewcRootfs(t, true)))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		image         func([]byte) []byte
		wantLayout    string
		wantSelection string
	}{
		{
			name: "partitioned",
			image: func(ext []byte) []byte {
				return buildPartitionedDisk(ext)
			},
			wantLayout:    "partitioned",
			wantSelection: "partition 1 (offset 512, length 10240)",
		},
		{
			name: "fixed offset",
			image: func(ext []byte) []byte {
				return buildOffsetDisk(ext, 0x100000)
			},
			wantLayout:    "fixed-offset",
			wantSelection: "fixed offset 1048576 (length 10240)",
		},
		{
			name: "scanned offset",
			image: func(ext []byte) []byte {
				return buildOffsetDisk(ext, 0x800000)
			},
			wantLayout:    "scanned-offset",
			wantSelection: "scanned offset 8388608 (length 10240)",
		},
		{
			name: "qcow2 partition",
			image: func(ext []byte) []byte {
				return buildQCOW2Disk(buildPartitionedDisk(ext))
			},
			wantLayout:    "qcow2",
			wantSelection: "partition 1 (offset 512, length 10240)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join(t.TempDir(), "firmware.out")
			if err := os.WriteFile(input, gzipBytes(t, tc.image(ext)), 0o600); err != nil {
				t.Fatal(err)
			}
			result := runCLISubprocess(t, []string{"inspect", input}, "")
			if result.code != 0 {
				t.Fatalf("exit = %d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
			}
			for _, want := range []string{
				"disk-layout: " + tc.wantLayout + "\n",
				"selected-volume: " + tc.wantSelection + "\n",
				"status: complete\n",
			} {
				if !strings.Contains(result.stdout, want) {
					t.Fatalf("stdout does not contain %q:\n%s", want, result.stdout)
				}
			}
		})
	}
}

func TestInspectReportRedactsRootfsDetailAndSanitisesBoundedReason(t *testing.T) {
	const secret = "ROOTFS-KEY-DETAIL-MUST-NOT-APPEAR"
	report := newInspectReport()
	report.setRootfsCrypto(&rootfsDecision{
		Family: "synthetic-family", Cipher: "synthetic-cipher", keyDetail: secret,
	})
	report.stop(inspectStageRequiredMembers, inspectStageRootfsCrypto,
		errors.New("firmware says \x1b[31m"+strings.Repeat("x", 700)))
	out, err := captureStdout(t, func() error {
		report.print()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("rootfs key detail was printed: %s", out)
	}
	if strings.Contains(out, "\x1b") || !strings.Contains(out, `\x1b[31m`) {
		t.Fatalf("dynamic report reason was not terminal-sanitised: %q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "reason: ") && len(line) > len("reason: ")+512 {
			t.Fatalf("reason was not bounded: %d bytes", len(line))
		}
	}
}

func TestClassifyRootfsPayloadXZExt(t *testing.T) {
	ext, err := gunzipOuter(syntheticDecryptImage(t, syntheticNewcRootfs(t, true)))
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	w, err := xz.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(ext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	decision, err := classifyRootfsPayload(compressed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Kind != "xz/ext" || decision.ext == nil {
		t.Fatalf("decision = %+v", decision)
	}
}

func rewriteGzipPrefix(t *testing.T, data, prefix []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	copy(plain, prefix)
	return gzipBytes(t, plain)
}

type stubMember struct {
	data []byte
	err  error
}

type stubVolume map[string]stubMember

func (v stubVolume) ReadFile(name string) ([]byte, error) {
	member, ok := v[name]
	if !ok {
		return nil, diskimage.ErrNotFound
	}
	return member.data, member.err
}

func buildPartitionedDisk(ext []byte) []byte {
	disk := make([]byte, 512+len(ext))
	copy(disk[512:], ext)
	disk[510] = 0x55
	disk[511] = 0xaa
	entry := disk[446:462]
	entry[4] = 0x83
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	binary.LittleEndian.PutUint32(entry[12:16], uint32(len(ext)/512))
	return disk
}

func buildOffsetDisk(ext []byte, offset int) []byte {
	disk := make([]byte, offset+len(ext))
	copy(disk[offset:], ext)
	return disk
}

func buildQCOW2Disk(guest []byte) []byte {
	const (
		clusterBits = 16
		clusterSize = 1 << clusterBits
	)
	image := make([]byte, 4*clusterSize)
	copy(image[:4], []byte{'Q', 'F', 'I', 0xfb})
	binary.BigEndian.PutUint32(image[4:8], 3)
	binary.BigEndian.PutUint32(image[20:24], clusterBits)
	binary.BigEndian.PutUint64(image[24:32], clusterSize)
	binary.BigEndian.PutUint32(image[36:40], 1)
	binary.BigEndian.PutUint64(image[40:48], clusterSize)
	binary.BigEndian.PutUint64(image[clusterSize:clusterSize+8], 2*clusterSize)
	binary.BigEndian.PutUint64(image[2*clusterSize:2*clusterSize+8], 3*clusterSize)
	copy(image[3*clusterSize:], guest)
	return image
}

func encryptSyntheticL1(plain, key []byte) []byte {
	out := make([]byte, len(plain))
	for block := 0; block < len(plain); block += 512 {
		end := min(block+512, len(plain))
		previous := byte(0xff)
		for i := block; i < end; i++ {
			keyOffset := (i - block) & 0x1f
			ciphertext := (plain[i] + byte(keyOffset)) ^ key[keyOffset] ^ previous
			out[i] = ciphertext
			previous = ciphertext
		}
	}
	return out
}

func directoryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func assertEmptyDirectory(t *testing.T, dir string) {
	t.Helper()
	if names := directoryNames(t, dir); len(names) != 0 {
		t.Fatalf("directory %s contains residue: %v", dir, names)
	}
}
