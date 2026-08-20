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
	if link != "./a/hello.txt" {
		t.Fatalf("symlink target = %q", link)
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

func TestUntarRejectsPathEscape(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../../etc/passwd", Mode: 0o644, Size: 0})
	_ = tw.Close()

	dest := t.TempDir()
	if err := Untar(bytes.NewReader(buf.Bytes()), dest); err == nil {
		t.Fatal("expected a path-escape error")
	}
}
