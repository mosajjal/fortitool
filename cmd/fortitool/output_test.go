package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	runErr := fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return string(out), runErr
}

func syntheticClearL1Image() []byte {
	plain := make([]byte, 512)
	copy(plain[12:16], []byte{0xff, 0x00, 0xaa, 0x55})
	copy(plain[16:46], []byte("SYNTH-v0.0.0-FW-build0000-test"))
	return plain
}

func gzipBytes(t *testing.T, plain []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func syntheticNewcRootfs(t *testing.T, trailer bool) []byte {
	return syntheticNewcRootfsWithTail(t, trailer, nil)
}

func syntheticNewcRootfsWithTail(t *testing.T, trailer bool, tail []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	writeEntry := func(name string, mode uint32, data []byte) {
		nameBytes := append([]byte(name), 0)
		header := fmt.Sprintf(
			"070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			archive.Len()+1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nameBytes), 0,
		)
		if len(header) != 110 {
			t.Fatalf("newc header length = %d", len(header))
		}
		archive.WriteString(header)
		archive.Write(nameBytes)
		for archive.Len()%4 != 0 {
			archive.WriteByte(0)
		}
		archive.Write(data)
		for archive.Len()%4 != 0 {
			archive.WriteByte(0)
		}
	}
	writeEntry("bin/init", 0o100755, []byte("synthetic init"))
	if trailer {
		writeEntry("TRAILER!!!", 0, nil)
	}
	archive.Write(tail)
	return gzipBytes(t, archive.Bytes())
}

func syntheticDecryptImage(t *testing.T, rootfs []byte) []byte {
	return syntheticDecryptImageWithMembers(t, []byte("synthetic flatkc"), rootfs)
}

func syntheticDecryptImageWithMembers(t *testing.T, flatkc, rootfs []byte) []byte {
	t.Helper()
	const (
		blockSize       = 1024
		inodesPerGroup  = 16
		inodeTableBlock = 3
		inodeBitmap     = 5
		rootDirBlock    = 6
		flatkcBlock     = 7
	)
	flatkcBlocks := (len(flatkc) + blockSize - 1) / blockSize
	rootfsBlocks := (len(rootfs) + blockSize - 1) / blockSize
	if flatkcBlocks > 12 || rootfsBlocks > 12 {
		t.Fatalf("synthetic members need %d/%d direct blocks", flatkcBlocks, rootfsBlocks)
	}
	rootfsBlock := flatkcBlock + flatkcBlocks
	totalBlocks := max(10, rootfsBlock+rootfsBlocks)
	if totalBlocks > inodesPerGroup {
		t.Fatalf("synthetic image needs %d blocks", totalBlocks)
	}
	image := make([]byte, totalBlocks*blockSize)
	block := func(number int) []byte {
		return image[number*blockSize : (number+1)*blockSize]
	}
	le16 := binary.LittleEndian.PutUint16
	le32 := binary.LittleEndian.PutUint32

	copy(image[12:16], []byte{0xff, 0x00, 0xaa, 0x55})
	copy(image[16:46], []byte("SYNTH-v0.0.0-FW-build0000-test"))

	superblock := block(1)
	le32(superblock[0:4], inodesPerGroup)
	le32(superblock[4:8], uint32(totalBlocks))
	le32(superblock[20:24], 1)
	le32(superblock[24:28], 0)
	le32(superblock[32:36], uint32(totalBlocks-1))
	le32(superblock[40:44], inodesPerGroup)
	le16(superblock[56:58], 0xef53)
	le32(superblock[76:80], 1)
	le16(superblock[88:90], 128)
	le32(superblock[96:100], 2)

	descriptor := block(2)
	le32(descriptor[4:8], inodeBitmap)
	le32(descriptor[8:12], inodeTableBlock)
	block(inodeBitmap)[0] = 0x0f

	writeInode := func(number uint32, mode uint16, size uint32, dataBlock, blocks uint32) {
		offset := inodeTableBlock*blockSize + int(number-1)*128
		inode := image[offset : offset+128]
		le16(inode[0:2], mode)
		le32(inode[4:8], size)
		for i := uint32(0); i < blocks; i++ {
			le32(inode[40+i*4:44+i*4], dataBlock+i)
		}
	}
	writeInode(2, 0o040755, blockSize, rootDirBlock, 1)
	writeInode(3, 0o100644, uint32(len(flatkc)), flatkcBlock, uint32(flatkcBlocks))
	writeInode(4, 0o100644, uint32(len(rootfs)), uint32(rootfsBlock), uint32(rootfsBlocks))

	type directoryEntry struct {
		inode    uint32
		fileType byte
		name     string
	}
	entries := []directoryEntry{
		{inode: 2, fileType: 2, name: "."},
		{inode: 2, fileType: 2, name: ".."},
		{inode: 3, fileType: 1, name: "flatkc"},
		{inode: 4, fileType: 1, name: "rootfs.gz"},
	}
	directory := block(rootDirBlock)
	offset := 0
	for index, entry := range entries {
		recordLength := (8 + len(entry.name) + 3) &^ 3
		if index == len(entries)-1 {
			recordLength = len(directory) - offset
		}
		le32(directory[offset:offset+4], entry.inode)
		le16(directory[offset+4:offset+6], uint16(recordLength))
		directory[offset+6] = byte(len(entry.name))
		directory[offset+7] = entry.fileType
		copy(directory[offset+8:offset+8+len(entry.name)], entry.name)
		offset += recordLength
	}
	copy(image[flatkcBlock*blockSize:], flatkc)
	copy(image[rootfsBlock*blockSize:], rootfs)
	return gzipBytes(t, image)
}

func TestCmdUnpackPublishesCompleteTree(t *testing.T) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	payload := []byte("complete")
	if err := tw.WriteHeader(&tar.Header{Name: "file", Mode: 0o644, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "archive.tar")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdUnpack(context.Background(), []string{"-o", output, input}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(output, "file"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("published payload = %q", got)
	}
	assertPrivateDirectory(t, output)
}

func TestCmdUnpackRejectsSecondGzipMemberWithoutPublication(t *testing.T) {
	var compressed bytes.Buffer
	for _, name := range []string{"first", "second"} {
		var archive bytes.Buffer
		tw := tar.NewWriter(&archive)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		zw := gzip.NewWriter(&compressed)
		if _, err := zw.Write(archive.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "multi.tar.gz")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, compressed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdUnpack(context.Background(), []string{"-o", output, input}); err == nil {
		t.Fatal("expected a second gzip member to be rejected")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("partial output was published: %v", err)
	}
}

func TestGunzipOuterRejectsTruncatedGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(bytes.Repeat([]byte("payload"), 64)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	truncated := buf.Bytes()[:buf.Len()-8]
	if _, err := gunzipOuter(truncated); err == nil {
		t.Fatal("expected truncated gzip to fail")
	}
}

func TestGunzipOuterAllowsFortiOSTrailingData(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte("decoded installer image")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("non-gzip installer tail")
	got, err := gunzipOuter(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "decoded installer image" {
		t.Fatalf("decoded data = %q", got)
	}
}

func TestValidateGzipMemberRejectsMalformedBodyAndTrailer(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(bytes.Repeat([]byte("rootfs payload"), 64)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	valid := buf.Bytes()
	corruptCRC := append([]byte{}, valid...)
	corruptCRC[len(corruptCRC)-8] ^= 0xff

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "malformed header", data: []byte{0x1f, 0x8b, 0x08}},
		{name: "truncated trailer", data: valid[:len(valid)-4]},
		{name: "corrupt CRC", data: corruptCRC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decryptRootfsAuto(context.Background(), nil, tc.data, false); err == nil {
				t.Fatal("expected malformed standalone gzip to fail")
			}
		})
	}
}

func TestValidateGzipMemberAllowsTailAndEnforcesExpansionLimit(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(bytes.Repeat([]byte("x"), 1025)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	validWithTail := append(append([]byte{}, buf.Bytes()...), []byte("Fortinet tail")...)
	if err := validateGzipMember(validWithTail, 1025); err != nil {
		t.Fatalf("complete first member with tail rejected: %v", err)
	}
	if err := validateGzipMember(validWithTail, 1024); err == nil {
		t.Fatal("expected gzip expansion past the limit to fail")
	}
}

func TestWriteNewFileRejectsExistingOutput(t *testing.T) {
	name := filepath.Join(t.TempDir(), "output")
	if err := os.WriteFile(name, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(name, []byte("replacement"), 0o644); err == nil {
		t.Fatal("expected existing-output error")
	}
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("existing output changed to %q", got)
	}
}

func TestWriteNewFilePublishesNewFileWithoutResidue(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "output")
	if err := writeNewFile(name, []byte("complete"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "complete" {
		t.Fatalf("published output = %q", got)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".output.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary output remains: %v", matches)
	}
}

func TestCmdL1PublishesPrivateStandaloneOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "image.out")
	output := filepath.Join(dir, "image.decrypted")
	if err := os.WriteFile(input, syntheticClearL1Image(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdL1(context.Background(), []string{"-o", output, input}); err != nil {
		t.Fatal(err)
	}
	assertPrivateFile(t, output)
}

func TestCmdRootfsPublishesValidatedPrivateStandaloneOutput(t *testing.T) {
	dir := t.TempDir()
	flatkc := filepath.Join(dir, "flatkc")
	rootfs := filepath.Join(dir, "rootfs.gz")
	output := filepath.Join(dir, "rootfs.gz.dec")
	if err := os.WriteFile(flatkc, []byte("unused for a plain rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte("synthetic rootfs")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootfs, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdRootfs(context.Background(), []string{"-o", output, flatkc, rootfs}); err != nil {
		t.Fatal(err)
	}
	assertPrivateFile(t, output)
}

func TestStagedOutputCommitRejectsRacedDestination(t *testing.T) {
	parent := t.TempDir()
	final := filepath.Join(parent, "output")
	staged, err := newStagedOutputDir(final)
	if err != nil {
		t.Fatal(err)
	}
	defer staged.Cleanup()
	if err := os.WriteFile(filepath.Join(staged.temp, "staged"), []byte("staged"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(final, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := staged.Commit(); err == nil {
		t.Fatal("expected raced output collision")
	}
	entries, err := os.ReadDir(final)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("raced destination was replaced: %v", entries)
	}
}

func TestRenamePortablePublishesNewDirectory(t *testing.T) {
	parent := t.TempDir()
	oldPath := filepath.Join(parent, "staged")
	newPath := filepath.Join(parent, "published")
	if err := os.Mkdir(oldPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldPath, "file"), []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renamePortable(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(newPath, "file"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "complete" {
		t.Fatalf("published content = %q", got)
	}
}

func TestRenamePortableRejectsExistingPath(t *testing.T) {
	parent := t.TempDir()
	oldPath := filepath.Join(parent, "staged")
	newPath := filepath.Join(parent, "published")
	if err := os.Mkdir(oldPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(newPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := renamePortable(oldPath, newPath); err == nil {
		t.Fatal("expected existing destination to be rejected")
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("staged directory changed after collision: %v", err)
	}
	entries, err := os.ReadDir(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("existing destination changed: %v", entries)
	}
}

func TestStagedOutputCleanupRemovesOnlyCreatedNestedParents(t *testing.T) {
	base := t.TempDir()
	existing := filepath.Join(base, "existing")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	createdParent := filepath.Join(existing, "new", "nested")
	staged, err := newStagedOutputDir(filepath.Join(createdParent, "output"))
	if err != nil {
		t.Fatal(err)
	}
	staged.Cleanup()
	if _, err := os.Lstat(filepath.Join(existing, "new")); !os.IsNotExist(err) {
		t.Fatalf("new output-parent chain remains after cleanup: %v", err)
	}
	if info, err := os.Stat(existing); err != nil || !info.IsDir() {
		t.Fatalf("pre-existing parent was removed or changed: %v", err)
	}
}

func TestCmdUnpackRejectsInputOutputCollision(t *testing.T) {
	input := filepath.Join(t.TempDir(), "archive.tar")
	if err := os.WriteFile(input, []byte("not a tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdUnpack(context.Background(), []string{"-o", input, input}); err == nil {
		t.Fatal("expected input/output collision")
	}
	got, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "not a tar" {
		t.Fatalf("input changed to %q", got)
	}
}

func TestCmdL1RejectsSameInputOutputPath(t *testing.T) {
	input := filepath.Join(t.TempDir(), "image.out")
	original := syntheticClearL1Image()
	if err := os.WriteFile(input, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdL1(context.Background(), []string{"-o", input, input}); err == nil {
		t.Fatal("expected same input/output path to fail")
	}
	got, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("same-path failure changed the input")
	}
}

func TestCmdL1RejectsHardLinkedInputOutputAlias(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "image.out")
	alias := filepath.Join(dir, "alias.out")
	original := syntheticClearL1Image()
	if err := os.WriteFile(input, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(input, alias); err != nil {
		t.Fatal(err)
	}
	if err := cmdL1(context.Background(), []string{"-o", alias, input}); err == nil {
		t.Fatal("expected hard-linked input/output alias to fail")
	}
	got, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("hard-link alias failure changed the input")
	}
}

func TestCmdUnpackRejectsHardLinkedOutputAlias(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "archive.tar")
	alias := filepath.Join(dir, "alias")
	if err := os.WriteFile(input, []byte("not a tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(input, alias); err != nil {
		t.Fatal(err)
	}
	if err := cmdUnpack(context.Background(), []string{"-o", alias, input}); err == nil {
		t.Fatal("expected hard-linked output collision")
	}
}

func TestCmdUnpackPreservesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "archive.tar")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, []byte("not reached"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "sentinel")
	if err := os.WriteFile(sentinel, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdUnpack(context.Background(), []string{"-o", output, input}); err == nil {
		t.Fatal("expected existing destination to fail")
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("existing destination changed to %q", got)
	}
}

func TestCmdUnpackRemovesStagingTreeAfterFailure(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "broken.tar")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, []byte("not a tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdUnpack(context.Background(), []string{"-o", output, input}); err == nil {
		t.Fatal("expected invalid archive to fail")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("partial output was published: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".output.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staging output remains: %v", matches)
	}
}

func TestCmdUnpackRemovesCreatedNestedParentsAfterFailure(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "broken.tar")
	createdTop := filepath.Join(dir, "new")
	output := filepath.Join(createdTop, "nested", "output")
	if err := os.WriteFile(input, []byte("not a tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdUnpack(context.Background(), []string{"-o", output, input}); err == nil {
		t.Fatal("expected invalid archive to fail")
	}
	if _, err := os.Lstat(createdTop); !os.IsNotExist(err) {
		t.Fatalf("created output-parent chain remains after failure: %v", err)
	}
}

func TestExtractNestedMembersPropagatesFailure(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootfs, "bin.tar.xz"), []byte("invalid xz"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractNestedMembers(rootfs); err == nil {
		t.Fatal("expected failed nested member to be fatal")
	}
}

func TestExtractNestedMembersDoesNotTreatDanglingSymlinkAsAbsent(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(rootfs, "bin.tar.xz")); err != nil {
		t.Fatal(err)
	}
	if err := extractNestedMembers(rootfs); err == nil {
		t.Fatal("expected dangling nested-member symlink to be fatal")
	}
}

func TestExtractDatafsPropagatesFailure(t *testing.T) {
	output := t.TempDir()
	if err := os.WriteFile(filepath.Join(output, "datafs.tar.gz"), []byte("invalid gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := extractDatafs(output); err == nil {
		t.Fatal("expected failed datafs extraction to be fatal")
	}
}

func TestExtractDatafsDoesNotTreatDanglingSymlinkAsAbsent(t *testing.T) {
	output := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(output, "datafs.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if _, err := extractDatafs(output); err == nil {
		t.Fatal("expected dangling datafs symlink to be fatal")
	}
}

func TestExtractDatafsDistinguishesOptionalAbsence(t *testing.T) {
	extracted, err := extractDatafs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if extracted {
		t.Fatal("absent datafs reported as extracted")
	}
}

func TestExtractRootfsPayloadRejectsShortUnknownInput(t *testing.T) {
	if err := extractRootfsPayload([]byte{0x01}, filepath.Join(t.TempDir(), "rootfs")); err == nil {
		t.Fatal("expected short unknown rootfs payload to fail")
	}
}

func TestCmdDecryptNewcPublishesPrivateOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "synthetic.out")
	output := filepath.Join(dir, "output")
	firmware := syntheticDecryptImage(t, syntheticNewcRootfs(t, true))
	if err := os.WriteFile(input, firmware, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, err := captureStdout(t, func() error {
		return cmdDecrypt(context.Background(), []string{"-o", output, input})
	})
	if err != nil {
		t.Fatalf("cmdDecrypt: %v", err)
	}
	if !strings.Contains(stdout, "DONE") {
		t.Fatalf("successful decrypt did not print completion: %q", stdout)
	}
	if got, err := os.ReadFile(filepath.Join(output, "rootfs", "bin", "init")); err != nil || string(got) != "synthetic init" {
		t.Fatalf("published init = %q, %v", got, err)
	}
	assertPrivateDirectory(t, output)
}

func TestCmdDecryptMalformedNewcDoesNotPublishOrLeaveResidue(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "synthetic.out")
	output := filepath.Join(dir, "output")
	firmware := syntheticDecryptImage(t, syntheticNewcRootfs(t, false))
	if err := os.WriteFile(input, firmware, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, err := captureStdout(t, func() error {
		return cmdDecrypt(context.Background(), []string{"-o", output, input})
	})
	if err == nil {
		t.Fatal("expected malformed newc to fail")
	}
	if strings.Contains(stdout, "DONE") {
		t.Fatalf("failed decrypt printed completion: %q", stdout)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("failed newc was published: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".output.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("failed newc left staging residue: %v", matches)
	}
}

func TestCmdDecryptRejectsNewcDataAfterTrailer(t *testing.T) {
	secondNewc := func() []byte {
		rootfs := syntheticNewcRootfs(t, true)
		zr, err := gzip.NewReader(bytes.NewReader(rootfs))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		if err := zr.Close(); err != nil {
			t.Fatal(err)
		}
		return plain
	}()
	trailingCRC := append([]byte(nil), secondNewc...)
	copy(trailingCRC[:6], "070702")

	for name, tail := range map[string][]byte{
		"second-newc":  secondNewc,
		"trailing-crc": trailingCRC,
		"nonzero":      {0, 0, 1, 0},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "synthetic.out")
			output := filepath.Join(dir, "output")
			firmware := syntheticDecryptImage(t, syntheticNewcRootfsWithTail(t, true, tail))
			if err := os.WriteFile(input, firmware, 0o600); err != nil {
				t.Fatal(err)
			}
			stdout, err := captureStdout(t, func() error {
				return cmdDecrypt(context.Background(), []string{"-o", output, input})
			})
			if err == nil {
				t.Fatal("expected trailing newc data to fail")
			}
			if strings.Contains(stdout, "DONE") {
				t.Fatalf("failed decrypt printed completion: %q", stdout)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("failed newc was published: %v", err)
			}
			matches, err := filepath.Glob(filepath.Join(dir, ".output.tmp-*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 0 {
				t.Fatalf("failed newc left staging residue: %v", matches)
			}
		})
	}
}

func TestCmdDecryptNewcAllowsZeroPadding(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "synthetic.out")
	output := filepath.Join(dir, "output")
	rootfs := syntheticNewcRootfsWithTail(t, true, make([]byte, 128))
	if err := os.WriteFile(input, syntheticDecryptImage(t, rootfs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDecrypt(context.Background(), []string{"-o", output, input}); err != nil {
		t.Fatalf("cmdDecrypt: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(output, "rootfs", "bin", "init")); err != nil || string(got) != "synthetic init" {
		t.Fatalf("published init = %q, %v", got, err)
	}
}

func TestCmdDecryptTrailingNewcDataPreservesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "synthetic.out")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, syntheticDecryptImage(t, syntheticNewcRootfsWithTail(t, true, []byte("070701"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "sentinel")
	if err := os.WriteFile(sentinel, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDecrypt(context.Background(), []string{"-o", output, input}); err == nil {
		t.Fatal("expected existing destination to be rejected")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "original" {
		t.Fatalf("existing destination changed: %q, %v", got, err)
	}
}

func TestCmdDecryptNewcPreservesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "synthetic.out")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, syntheticDecryptImage(t, syntheticNewcRootfs(t, true)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "sentinel")
	if err := os.WriteFile(sentinel, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDecrypt(context.Background(), []string{"-o", output, input}); err == nil {
		t.Fatal("expected existing destination to be rejected")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "original" {
		t.Fatalf("existing destination changed: %q, %v", got, err)
	}
}

func TestCmdDecryptFailureDoesNotPublishOrPrintDone(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "invalid.out")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, bytes.Repeat([]byte{0x7a}, 1536), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, err := captureStdout(t, func() error {
		return cmdDecrypt(context.Background(), []string{"-o", output, input})
	})
	if err == nil {
		t.Fatal("expected incomplete decrypt to fail")
	}
	if strings.Contains(stdout, "DONE") {
		t.Fatalf("incomplete decrypt printed success: %q", stdout)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("incomplete decrypt published output: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".output.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("incomplete decrypt left staging residue: %v", matches)
	}
}

func TestRecoveredKeysAreRedactedByDefault(t *testing.T) {
	key := []byte("synthetic-test-key-material")
	redacted := formatRecoveredKey(key, false)
	if bytes.Contains([]byte(redacted), key) {
		t.Fatalf("default L1 message exposed key: %q", redacted)
	}
	shown := formatRecoveredKey(key, true)
	if !bytes.Contains([]byte(shown), key) {
		t.Fatalf("--show-keys message omitted key: %q", shown)
	}
	unsafeKey := []byte("synthetic\x1bkey\n")
	shown = formatRecoveredKey(unsafeKey, true)
	if strings.ContainsAny(shown, "\x1b\n") || !strings.Contains(shown, `\x1b`) || !strings.Contains(shown, `\x0a`) {
		t.Fatalf("--show-keys message was not terminal-safe: %q", shown)
	}

	detail := "seed=synthetic-test-seed aes_key=synthetic-test-aes-key"
	if got := formatRootfsKeyDetail(detail, false); got == detail || bytes.Contains([]byte(got), []byte("synthetic-test-seed")) {
		t.Fatalf("default rootfs message exposed detail: %q", got)
	}
	if got := formatRootfsKeyDetail(detail, true); got != detail {
		t.Fatalf("--show-keys detail = %q", got)
	}
	unsafeDetail := "seed=synthetic\x1bseed\n"
	if got := formatRootfsKeyDetail(unsafeDetail, true); strings.ContainsAny(got, "\x1b\n") || !strings.Contains(got, `\x1b`) || !strings.Contains(got, `\x0a`) {
		t.Fatalf("--show-keys detail was not terminal-safe: %q", got)
	}
}
