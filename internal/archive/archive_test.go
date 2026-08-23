package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulikunitz/xz"
)

type testFile struct {
	name string
	body string
}

type testTarEntry struct {
	header tar.Header
	body   []byte
}

func buildTarEntries(t *testing.T, entries []testTarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		hdr := entry.header
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			hdr.Size = int64(len(entry.body))
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if len(entry.body) > 0 {
			if _, err := tw.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildTar(t *testing.T, files []testFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: f.name,
			Mode: 0o644,
			Size: int64(len(f.body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: "./link", Typeflag: tar.TypeSymlink, Linkname: "./a/hello.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractGzipTar(t *testing.T) {
	tarData := buildTar(t, []testFile{
		{"./a/hello.txt", "hello world"},
		{"./a/b/nested.txt", "nested content"},
	})
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(tarData); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if err := ExtractGzipTar(gz.Bytes(), dest); err != nil {
		t.Fatalf("ExtractGzipTar: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "a", "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q", got)
	}
	got2, err := os.ReadFile(filepath.Join(dest, "a", "b", "nested.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != "nested content" {
		t.Fatalf("got %q", got2)
	}
	link, err := os.Readlink(filepath.Join(dest, "link"))
	if err != nil {
		t.Fatal(err)
	}
	if link != "a/hello.txt" {
		t.Fatalf("symlink target = %q", link)
	}
}

func TestExtractGzipTarRejectsTruncatedMember(t *testing.T) {
	tarData := buildTar(t, []testFile{{"file", "complete tar payload"}})
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(tarData); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	truncated := gz.Bytes()[:gz.Len()-8]
	if err := ExtractGzipTar(truncated, filepath.Join(t.TempDir(), "output")); err == nil {
		t.Fatal("expected a truncated gzip member to fail")
	}
}

func TestExtractGzipTarAllowsTrailingData(t *testing.T) {
	tarData := buildTar(t, []testFile{{"file", "complete tar payload"}})
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(tarData); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	gz.WriteString("non-gzip FortiOS trailer")

	dest := t.TempDir()
	if err := ExtractGzipTar(gz.Bytes(), dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "file"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "complete tar payload" {
		t.Fatalf("payload = %q", got)
	}
}

func TestExtractXZTar(t *testing.T) {
	tarData := buildTar(t, []testFile{{"./bin/init", "#!/bin/fake\n"}})
	var xzBuf bytes.Buffer
	xw, err := xz.NewWriter(&xzBuf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xw.Write(tarData); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if err := ExtractXZTar(xzBuf.Bytes(), dest); err != nil {
		t.Fatalf("ExtractXZTar: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "bin", "init"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "#!/bin/fake\n" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractXZTarRejectsTruncatedMember(t *testing.T) {
	tarData := buildTar(t, []testFile{{"file", "complete tar payload"}})
	var xzBuf bytes.Buffer
	xw, err := xz.NewWriter(&xzBuf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xw.Write(tarData); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	truncated := xzBuf.Bytes()[:xzBuf.Len()-12]
	if err := ExtractXZTar(truncated, filepath.Join(t.TempDir(), "output")); err == nil {
		t.Fatal("expected a truncated XZ member to fail")
	}
}

func TestUntarRejectsPathEscape(t *testing.T) {
	for _, name := range []string{"../../etc/passwd", `..\..\outside`} {
		t.Run(name, func(t *testing.T) {
			tarData := buildTarEntries(t, []testTarEntry{{
				header: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644},
			}})
			if err := Untar(bytes.NewReader(tarData), t.TempDir()); err == nil {
				t.Fatal("expected a path-escape error")
			}
		})
	}
}

func TestUntarRejectsEscapingSymlinkTarget(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: "../../outside"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := Untar(bytes.NewReader(buf.Bytes()), t.TempDir()); err == nil {
		t.Fatal("expected an escaping-symlink error")
	}
}

func TestUntarRejectsArchiveCreatedEscapingSymlinkFollowedByWrite(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "dest")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	relOutside, err := filepath.Rel(dest, outside)
	if err != nil {
		t.Fatal(err)
	}
	tarData := buildTarEntries(t, []testTarEntry{
		{header: tar.Header{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: filepath.ToSlash(relOutside)}},
		{header: tar.Header{Name: "escape/written", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("unsafe")},
	})

	if err := Untar(bytes.NewReader(tarData), dest); err == nil {
		t.Fatal("expected an archive-created escaping symlink to fail")
	}
	if _, err := os.Lstat(filepath.Join(outside, "written")); !os.IsNotExist(err) {
		t.Fatalf("outside path changed: %v", err)
	}
}

func TestUntarRejectsArchiveCreatedSymlinkAncestor(t *testing.T) {
	tarData := buildTarEntries(t, []testTarEntry{
		{header: tar.Header{Name: "real", Typeflag: tar.TypeDir, Mode: 0o755}},
		{header: tar.Header{Name: "alias", Typeflag: tar.TypeSymlink, Linkname: "real"}},
		{header: tar.Header{Name: "alias/written", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("aliased")},
	})
	dest := t.TempDir()
	if err := Untar(bytes.NewReader(tarData), dest); err == nil {
		t.Fatal("expected traversal through an archive-created symlink to fail")
	}
	if _, err := os.Lstat(filepath.Join(dest, "real", "written")); !os.IsNotExist(err) {
		t.Fatalf("symlink traversal created an aliased output: %v", err)
	}
}

func TestUntarRebasesAbsoluteSymlinkTarget(t *testing.T) {
	tarData := buildTarEntries(t, []testTarEntry{{
		header: tar.Header{Name: "usr/bin/tool", Typeflag: tar.TypeSymlink, Linkname: "/sbin/init"},
	}})
	dest := t.TempDir()
	if err := Untar(bytes.NewReader(tarData), dest); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(dest, "usr", "bin", "tool"))
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Join("..", "..", "sbin", "init") {
		t.Fatalf("rebased target = %q", target)
	}
}

func TestUntarRejectsPreExistingSymlinkAncestor(t *testing.T) {
	dest := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dest, "escape")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "escape/written", Mode: 0o644, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := Untar(bytes.NewReader(buf.Bytes()), dest); err == nil {
		t.Fatal("expected a pre-existing-symlink error")
	}
	if _, err := os.Stat(filepath.Join(outside, "written")); !os.IsNotExist(err) {
		t.Fatalf("outside path changed: %v", err)
	}
}

func TestUntarRejectsSymlinkDestinationRoot(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	dest := filepath.Join(parent, "output")
	if err := os.Symlink(outside, dest); err != nil {
		t.Fatal(err)
	}
	tarData := buildTar(t, []testFile{{"written", "unsafe"}})
	if err := Untar(bytes.NewReader(tarData), dest); err == nil {
		t.Fatal("expected a symlink destination root to fail")
	}
	if _, err := os.Lstat(filepath.Join(outside, "written")); !os.IsNotExist(err) {
		t.Fatalf("outside path changed: %v", err)
	}
}

func TestUntarRejectsDuplicateOutput(t *testing.T) {
	tarData := buildTar(t, []testFile{{"duplicate", "first"}, {"duplicate", "second"}})
	if err := Untar(bytes.NewReader(tarData), t.TempDir()); err == nil {
		t.Fatal("expected duplicate output collision")
	}
}

func TestUntarRejectsNormalisedPathCollision(t *testing.T) {
	tarData := buildTar(t, []testFile{{"dir//file", "first"}, {"dir/file", "second"}})
	if err := Untar(bytes.NewReader(tarData), t.TempDir()); err == nil {
		t.Fatal("expected normalised-path output collision")
	}
}

func TestUntarRejectsFileDirectoryCollisions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []testTarEntry
	}{
		{
			name: "directory then file",
			entries: []testTarEntry{
				{header: tar.Header{Name: "node", Typeflag: tar.TypeDir, Mode: 0o755}},
				{header: tar.Header{Name: "node", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("file")},
			},
		},
		{
			name: "file then directory",
			entries: []testTarEntry{
				{header: tar.Header{Name: "node", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("file")},
				{header: tar.Header{Name: "node", Typeflag: tar.TypeDir, Mode: 0o755}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Untar(bytes.NewReader(buildTarEntries(t, tc.entries)), t.TempDir()); err == nil {
				t.Fatal("expected file/directory output collision")
			}
		})
	}
}

func TestUntarPreservesExistingOutput(t *testing.T) {
	dest := t.TempDir()
	target := filepath.Join(dest, "existing")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	tarData := buildTar(t, []testFile{{"existing", "replacement"}})
	if err := Untar(bytes.NewReader(tarData), dest); err == nil {
		t.Fatal("expected existing-output collision")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("existing output changed to %q", got)
	}
}

func TestUntarMergesIntoExistingDirectory(t *testing.T) {
	dest := t.TempDir()
	if err := os.Mkdir(filepath.Join(dest, "existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	tarData := buildTarEntries(t, []testTarEntry{
		{header: tar.Header{Name: "existing", Typeflag: tar.TypeDir, Mode: 0o755}},
		{header: tar.Header{Name: "existing/new", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("new")},
	})
	if err := Untar(bytes.NewReader(tarData), dest); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "existing", "new")); err != nil || string(got) != "new" {
		t.Fatalf("merged output = %q, %v", got, err)
	}
}

func TestUntarRejectsMissingHardLinkTarget(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "hardlink", Typeflag: tar.TypeLink, Linkname: "missing"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Untar(bytes.NewReader(buf.Bytes()), t.TempDir()); err == nil {
		t.Fatal("expected missing hard-link target error")
	}
}

func TestUntarCreatesSafeHardLink(t *testing.T) {
	tarData := buildTarEntries(t, []testTarEntry{
		{header: tar.Header{Name: "source", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("content")},
		{header: tar.Header{Name: "hardlink", Typeflag: tar.TypeLink, Linkname: "source"}},
	})
	dest := t.TempDir()
	if err := Untar(bytes.NewReader(tarData), dest); err != nil {
		t.Fatal(err)
	}
	source, err := os.Stat(filepath.Join(dest, "source"))
	if err != nil {
		t.Fatal(err)
	}
	linked, err := os.Stat(filepath.Join(dest, "hardlink"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(source, linked) {
		t.Fatal("safe hard link was not preserved")
	}
}

func TestUntarRejectsUnsafeHardLinkTarget(t *testing.T) {
	tarData := buildTarEntries(t, []testTarEntry{{
		header: tar.Header{Name: "hardlink", Typeflag: tar.TypeLink, Linkname: "../outside"},
	}})
	if err := Untar(bytes.NewReader(tarData), t.TempDir()); err == nil {
		t.Fatal("expected unsafe hard-link target error")
	}
}

func TestUntarRejectsUnsupportedEntryTypes(t *testing.T) {
	for _, typeflag := range []byte{tar.TypeChar, tar.TypeBlock, tar.TypeFifo, tar.TypeCont} {
		t.Run(string([]byte{typeflag}), func(t *testing.T) {
			tarData := buildTarEntries(t, []testTarEntry{{
				header: tar.Header{Name: "unsupported", Typeflag: typeflag, Mode: 0o600},
			}})
			if err := Untar(bytes.NewReader(tarData), t.TempDir()); err == nil {
				t.Fatalf("expected tar type %q to fail", typeflag)
			}
		})
	}
}

func TestUntarAcceptsGNURegularSparseRepresentation(t *testing.T) {
	tarData := buildTarEntries(t, []testTarEntry{{
		header: tar.Header{Name: "sparse", Typeflag: tar.TypeGNUSparse, Mode: 0o600, Format: tar.FormatGNU},
	}})
	dest := t.TempDir()
	if err := Untar(bytes.NewReader(tarData), dest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dest, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("sparse file size = %d, want 0", info.Size())
	}
}

func TestUntarRejectsHardLinkTargetThroughSymlink(t *testing.T) {
	tarData := buildTarEntries(t, []testTarEntry{
		{header: tar.Header{Name: "real/source", Typeflag: tar.TypeReg, Mode: 0o644}, body: []byte("source")},
		{header: tar.Header{Name: "alias", Typeflag: tar.TypeSymlink, Linkname: "real"}},
		{header: tar.Header{Name: "hardlink", Typeflag: tar.TypeLink, Linkname: "alias/source"}},
	})
	if err := Untar(bytes.NewReader(tarData), t.TempDir()); err == nil {
		t.Fatal("expected hard-link target through symlink to fail")
	}
}
