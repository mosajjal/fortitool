package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
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
