package archive

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type newcTestEntry struct {
	name     string
	mode     uint32
	ino      uint32
	nlink    uint32
	devMajor uint32
	devMinor uint32
	data     []byte
}

func buildNewc(t *testing.T, entries []newcTestEntry, trailer bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	writeEntry := func(entry newcTestEntry) {
		if entry.ino == 0 {
			entry.ino = uint32(buf.Len() + 1)
		}
		fileType := entry.mode & cpioModeTypeMask
		isSpecial := fileType == cpioModeBlock || fileType == cpioModeChar || fileType == cpioModeFIFO || fileType == cpioModeSocket
		if entry.nlink == 0 && fileType != cpioModeDir && !isSpecial {
			entry.nlink = 1
		}
		name := append([]byte(entry.name), 0)
		header := fmt.Sprintf(
			"%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			newcMagic, entry.ino, entry.mode, 0, 0, entry.nlink, 0,
			len(entry.data), entry.devMajor, entry.devMinor, 0, 0, len(name), 0,
		)
		if len(header) != newcHeaderSize {
			t.Fatalf("newc header length = %d", len(header))
		}
		buf.WriteString(header)
		buf.Write(name)
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
		buf.Write(entry.data)
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
	}
	for _, entry := range entries {
		writeEntry(entry)
	}
	if trailer {
		writeEntry(newcTestEntry{name: cpioTrailer})
	}
	return buf.Bytes()
}

func gzipTestData(t *testing.T, plain []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestExtractNewc(t *testing.T) {
	archive := buildNewc(t, []newcTestEntry{
		{name: ".", mode: cpioModeDir | 0o755},
		{name: "etc", mode: cpioModeDir | 0o755},
		{name: "etc/config", mode: cpioModeRegular | 0o640, data: []byte("config")},
		{name: "empty", mode: cpioModeRegular | 0o644},
		{name: "config-link", mode: cpioModeSymlink | 0o777, data: []byte("/etc/config")},
		{name: "hard-a", mode: cpioModeRegular | 0o600, ino: 50, nlink: 2, devMajor: 1},
		{name: "hard-b", mode: cpioModeRegular | 0o600, ino: 50, nlink: 2, devMajor: 1, data: []byte("linked")},
	}, true)
	dest := t.TempDir()
	if err := ExtractNewc(bytes.NewReader(archive), dest); err != nil {
		t.Fatalf("ExtractNewc: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "etc", "config")); err != nil || string(got) != "config" {
		t.Fatalf("config = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "empty")); err != nil || len(got) != 0 {
		t.Fatalf("empty = %q, %v", got, err)
	}
	if got, err := os.Readlink(filepath.Join(dest, "config-link")); err != nil || got != filepath.FromSlash("etc/config") {
		t.Fatalf("config-link = %q, %v", got, err)
	}
	a, err := os.Stat(filepath.Join(dest, "hard-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(dest, "hard-b"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Fatal("hard-link identity was not preserved")
	}
}

func TestExtractNewcPaddingBoundaries(t *testing.T) {
	entries := []newcTestEntry{
		{name: "a", mode: cpioModeRegular | 0o644, data: []byte("1")},
		{name: "bb", mode: cpioModeRegular | 0o644, data: []byte("22")},
		{name: "ccc", mode: cpioModeRegular | 0o644, data: []byte("333")},
		{name: "dddd", mode: cpioModeRegular | 0o644, data: []byte("4444")},
	}
	dest := t.TempDir()
	if err := ExtractNewc(bytes.NewReader(buildNewc(t, entries, true)), dest); err != nil {
		t.Fatalf("ExtractNewc: %v", err)
	}
	for _, entry := range entries {
		got, err := os.ReadFile(filepath.Join(dest, entry.name))
		if err != nil || !bytes.Equal(got, entry.data) {
			t.Fatalf("%s = %q, %v", entry.name, got, err)
		}
	}
}

func TestExtractGzipRootfsNewc(t *testing.T) {
	plain := buildNewc(t, []newcTestEntry{{name: "init", mode: cpioModeRegular | 0o755, data: []byte("synthetic")}}, true)
	dest := t.TempDir()
	if err := ExtractGzipRootfs(gzipTestData(t, plain), dest); err != nil {
		t.Fatalf("ExtractGzipRootfs: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "init")); err != nil || string(got) != "synthetic" {
		t.Fatalf("init = %q, %v", got, err)
	}
}

func TestExtractGzipRootfsTar(t *testing.T) {
	plain := buildTar(t, []testFile{{name: "init", body: "synthetic"}})
	dest := t.TempDir()
	if err := ExtractGzipRootfs(gzipTestData(t, plain), dest); err != nil {
		t.Fatalf("ExtractGzipRootfs: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "init")); err != nil || string(got) != "synthetic" {
		t.Fatalf("init = %q, %v", got, err)
	}
}

func TestClassifyGzipRootfsMatchesExtractionDispatch(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want GzipRootfsFormat
	}{
		{
			name: "newc",
			data: gzipTestData(t, buildNewc(t, []newcTestEntry{{name: "init", mode: cpioModeRegular | 0o755}}, true)),
			want: GzipRootfsNewc,
		},
		{
			name: "tar",
			data: gzipTestData(t, buildTar(t, []testFile{{name: "init", body: "synthetic"}})),
			want: GzipRootfsTar,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ClassifyGzipRootfs(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("format = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyGzipRootfsRejectsUnsupportedOrInvalidInnerContainer(t *testing.T) {
	crc := buildNewc(t, nil, true)
	copy(crc[:len(newcCRCMagic)], newcCRCMagic)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "unsupported CRC newc", data: gzipTestData(t, crc), want: newcCRCMagic},
		{name: "invalid tar", data: gzipTestData(t, []byte("not a tar archive")), want: "tar"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ClassifyGzipRootfs(tc.data); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("classification error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestExtractGzipRootfsValidatesNewcMember(t *testing.T) {
	plain := buildNewc(t, []newcTestEntry{{name: "init", mode: cpioModeRegular | 0o755, data: []byte("synthetic")}}, true)
	compressed := gzipTestData(t, plain)
	compressed = compressed[:len(compressed)-8]
	if err := ExtractGzipRootfs(compressed, t.TempDir()); err == nil {
		t.Fatal("expected a truncated gzip member to fail")
	}
}

func TestExtractGzipRootfsAllowsTrailingData(t *testing.T) {
	plain := buildNewc(t, []newcTestEntry{{name: "init", mode: cpioModeRegular | 0o755}}, true)
	compressed := append(gzipTestData(t, plain), []byte("non-gzip FortiOS trailer")...)
	if err := ExtractGzipRootfs(compressed, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestExtractGzipRootfsRejectsSecondMember(t *testing.T) {
	plain := buildNewc(t, []newcTestEntry{{name: "init", mode: cpioModeRegular | 0o755}}, true)
	first := gzipTestData(t, plain)
	second := gzipTestData(t, plain)
	if err := ExtractGzipRootfs(append(first, second...), t.TempDir()); err == nil {
		t.Fatal("expected a second gzip member to be rejected")
	}
}

func TestExtractGzipRootfsRejectsCRCNewc(t *testing.T) {
	plain := buildNewc(t, nil, true)
	copy(plain[:len(newcCRCMagic)], newcCRCMagic)
	err := ExtractGzipRootfs(gzipTestData(t, plain), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), newcCRCMagic) {
		t.Fatalf("expected explicit %s rejection, got %v", newcCRCMagic, err)
	}
}

func TestExtractNewcRejectsUnsafePaths(t *testing.T) {
	for _, name := range []string{"", "/absolute", "../escape", "a/../escape", `a\..\escape`, "bad\x00name"} {
		t.Run(fmt.Sprintf("%x", name), func(t *testing.T) {
			data := buildNewc(t, []newcTestEntry{{name: name, mode: cpioModeRegular | 0o644}}, true)
			if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestSafeCPIOPathDepthBound(t *testing.T) {
	allowed := strings.Repeat("d/", maxCPIOPathDepth-1) + "file"
	if _, err := safeCPIOPath(allowed); err != nil {
		t.Fatalf("maximum path depth was rejected: %v", err)
	}

	rejected := strings.Repeat("d/", maxCPIOPathDepth) + "file"
	data := buildNewc(t, []newcTestEntry{{name: rejected, mode: cpioModeRegular | 0o644}}, true)
	err := ExtractNewc(bytes.NewReader(data), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "path components") {
		t.Fatalf("expected excessive path depth to be rejected, got %v", err)
	}
}

func TestExtractNewcRejectsEscapingSymlink(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{{name: "dir/link", mode: cpioModeSymlink | 0o777, data: []byte("../../outside")}}, true)
	if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("expected escaping symlink target to be rejected")
	}
}

func TestExtractNewcRejectsArchiveCreatedSymlinkAncestor(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{
		{name: "real", mode: cpioModeDir | 0o755},
		{name: "alias", mode: cpioModeSymlink | 0o777, data: []byte("real")},
		{name: "alias/file", mode: cpioModeRegular | 0o644, data: []byte("escape")},
	}, true)
	if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("expected symlink ancestor to be rejected")
	}
}

func TestExtractNewcRejectsPreExistingSymlinkAncestor(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "dest")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dest, "alias")); err != nil {
		t.Fatal(err)
	}
	data := buildNewc(t, []newcTestEntry{{name: "alias/file", mode: cpioModeRegular | 0o644, data: []byte("escape")}}, true)
	if err := ExtractNewc(bytes.NewReader(data), dest); err == nil {
		t.Fatal("expected pre-existing symlink ancestor to be rejected")
	}
	if _, err := os.Lstat(filepath.Join(outside, "file")); !os.IsNotExist(err) {
		t.Fatalf("outside file exists: %v", err)
	}
}

func TestExtractNewcRejectsCollisions(t *testing.T) {
	tests := map[string][]newcTestEntry{
		"duplicate": {
			{name: "same", mode: cpioModeRegular | 0o644},
			{name: "same", mode: cpioModeRegular | 0o644},
		},
		"normalised": {
			{name: "a/b", mode: cpioModeRegular | 0o644},
			{name: "a/./b", mode: cpioModeRegular | 0o644},
		},
		"file-directory": {
			{name: "a", mode: cpioModeRegular | 0o644},
			{name: "a/b", mode: cpioModeRegular | 0o644},
		},
		"implicit-directory": {
			{name: "a/b", mode: cpioModeRegular | 0o644},
			{name: "a", mode: cpioModeDir | 0o755},
		},
		"special-then-child": {
			{name: "a", mode: cpioModeChar | 0o600},
			{name: "a/b", mode: cpioModeRegular | 0o644},
		},
		"child-then-special": {
			{name: "a/b", mode: cpioModeRegular | 0o644},
			{name: "a", mode: cpioModeChar | 0o600},
		},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ExtractNewc(bytes.NewReader(buildNewc(t, entries, true)), t.TempDir()); err == nil {
				t.Fatal("expected collision error")
			}
		})
	}
}

func TestExtractNewcPreservesExistingOutput(t *testing.T) {
	dest := t.TempDir()
	target := filepath.Join(dest, "existing")
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := buildNewc(t, []newcTestEntry{{name: "existing", mode: cpioModeRegular | 0o644, data: []byte("replacement")}}, true)
	if err := ExtractNewc(bytes.NewReader(data), dest); err == nil {
		t.Fatal("expected existing-output collision")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "sentinel" {
		t.Fatalf("existing output changed: %q, %v", got, err)
	}
}

func TestExtractNewcRejectsMalformedHeaders(t *testing.T) {
	valid := buildNewc(t, nil, true)
	tests := map[string][]byte{
		"hex": func() []byte {
			data := append([]byte(nil), valid...)
			data[6] = 'z'
			return data
		}(),
		"oversized-name": func() []byte {
			data := append([]byte(nil), valid...)
			copy(data[6+11*8:6+12*8], "ffffffff")
			return data
		}(),
		"nonzero-check": func() []byte {
			data := append([]byte(nil), valid...)
			copy(data[6+12*8:6+13*8], "00000001")
			return data
		}(),
		"crc-form": func() []byte {
			data := append([]byte(nil), valid...)
			copy(data[:6], newcCRCMagic)
			return data
		}(),
		"oversized-symlink": func() []byte {
			data := buildNewc(t, []newcTestEntry{{name: "link", mode: cpioModeSymlink | 0o777, data: []byte("target")}}, true)
			copy(data[6+6*8:6+7*8], "ffffffff")
			return data
		}(),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
				t.Fatal("expected malformed header error")
			}
		})
	}
}

func TestExtractNewcRejectsMalformedNames(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"not-nul-terminated": func(data []byte) { data[newcHeaderSize+len("file")] = 'x' },
		"embedded-nul":       func(data []byte) { data[newcHeaderSize+1] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			data := buildNewc(t, []newcTestEntry{{name: "file", mode: cpioModeRegular | 0o644}}, true)
			mutate(data)
			if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
				t.Fatal("expected malformed name error")
			}
		})
	}
}

func TestExtractNewcRejectsInvalidPadding(t *testing.T) {
	tests := map[string][]byte{
		"name-nonzero": func() []byte {
			data := buildNewc(t, []newcTestEntry{{name: "aa", mode: cpioModeRegular | 0o644}}, true)
			data[newcHeaderSize+len("aa")+1] = 1
			return data
		}(),
		"data-nonzero": func() []byte {
			data := buildNewc(t, []newcTestEntry{{name: "a", mode: cpioModeRegular | 0o644, data: []byte("x")}}, true)
			data[newcHeaderSize+len("a")+1+1] = 1
			return data
		}(),
		"data-truncated": func() []byte {
			data := buildNewc(t, []newcTestEntry{{name: "a", mode: cpioModeRegular | 0o644, data: []byte("x")}}, true)
			return data[:newcHeaderSize+len("a")+1+1+2]
		}(),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
				t.Fatal("expected padding error")
			}
		})
	}
}

func TestExtractNewcRejectsTruncation(t *testing.T) {
	full := buildNewc(t, []newcTestEntry{{name: "file", mode: cpioModeRegular | 0o644, data: []byte("content")}}, true)
	for _, cut := range []int{1, newcHeaderSize + 2, newcHeaderSize + 8, newcHeaderSize + 8 + 3} {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			if err := ExtractNewc(bytes.NewReader(full[:cut]), t.TempDir()); err == nil {
				t.Fatal("expected truncation error")
			}
		})
	}
}

func TestExtractNewcRequiresTrailer(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{{name: "file", mode: cpioModeRegular | 0o644}}, false)
	err := ExtractNewc(bytes.NewReader(data), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), cpioTrailer) {
		t.Fatalf("expected missing trailer error, got %v", err)
	}
}

func TestExtractNewcRejectsTrailerData(t *testing.T) {
	data := buildNewc(t, nil, true)
	copy(data[6+6*8:6+7*8], "00000001")
	if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("expected trailer data to be rejected")
	}
}

func TestExtractNewcValidatesDataAfterTrailer(t *testing.T) {
	first := buildNewc(t, []newcTestEntry{{name: "first", mode: cpioModeRegular | 0o644}}, true)
	second := buildNewc(t, []newcTestEntry{{name: "second", mode: cpioModeRegular | 0o644}}, true)
	crc := append([]byte(nil), second...)
	copy(crc[:len(newcCRCMagic)], newcCRCMagic)

	tests := map[string][]byte{
		"second-newc":  append(append([]byte(nil), first...), second...),
		"trailing-crc": append(append([]byte(nil), first...), crc...),
		"nonzero":      append(append([]byte(nil), first...), 0, 0, 1, 0),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			dest := t.TempDir()
			err := ExtractNewc(bytes.NewReader(data), dest)
			if err == nil || !strings.Contains(err.Error(), "after TRAILER!!!") {
				t.Fatalf("expected trailing-data rejection, got %v", err)
			}
			if _, err := os.Lstat(filepath.Join(dest, "second")); !os.IsNotExist(err) {
				t.Fatalf("second archive was extracted: %v", err)
			}
		})
	}
}

func TestExtractNewcAllowsZeroPaddingAfterTrailer(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{{name: "file", mode: cpioModeRegular | 0o644, data: []byte("content")}}, true)
	data = append(data, make([]byte, 512-len(data)%512)...)
	dest := t.TempDir()
	if err := ExtractNewc(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractNewc: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "file")); err != nil || string(got) != "content" {
		t.Fatalf("file = %q, %v", got, err)
	}
}

func TestExtractNewcDoesNotMaterialiseSpecialNodes(t *testing.T) {
	for _, mode := range []uint32{cpioModeBlock, cpioModeChar, cpioModeFIFO, cpioModeSocket} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			entry := newcTestEntry{name: "special", mode: mode | 0o600}
			entry.nlink = 0
			data := buildNewc(t, []newcTestEntry{entry}, true)
			dest := t.TempDir()
			if err := ExtractNewc(bytes.NewReader(data), dest); err != nil {
				t.Fatalf("ExtractNewc: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(dest, "special")); !os.IsNotExist(err) {
				t.Fatalf("special node was materialised: %v", err)
			}
		})
	}
}

func TestExtractNewcRejectsUnsupportedType(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{{name: "unsupported", mode: 0o150000 | 0o644}}, true)
	if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("expected unsupported file type to be rejected")
	}
}

func TestExtractNewcRejectsSpecialNodeData(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{{name: "device", mode: cpioModeChar | 0o600, data: []byte("x")}}, true)
	if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("expected special-node data to be rejected")
	}
}

func TestExtractNewcRejectsUnresolvedHardLink(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{{name: "only-link", mode: cpioModeRegular | 0o644, ino: 9, nlink: 2}}, true)
	if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("expected unresolved hard link to be rejected")
	}
}

func TestExtractNewcRejectsIncompleteDataHardLinkGroup(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{{
		name: "only-data", mode: cpioModeRegular | 0o644,
		ino: 9, nlink: 2, data: []byte("content"),
	}}, true)
	if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("expected incomplete data-bearing hard-link group to be rejected")
	}
}

func TestExtractNewcRejectsInconsistentHardLinkMetadata(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{
		{name: "first", mode: cpioModeRegular | 0o600, ino: 9, nlink: 2},
		{name: "second", mode: cpioModeRegular | 0o640, ino: 9, nlink: 2, data: []byte("content")},
	}, true)
	if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("expected inconsistent hard-link metadata to be rejected")
	}
}

func TestExtractNewcRejectsMultipleHardLinkDataMembers(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{
		{name: "first", mode: cpioModeRegular | 0o600, ino: 9, nlink: 2, data: []byte("first")},
		{name: "second", mode: cpioModeRegular | 0o600, ino: 9, nlink: 2, data: []byte("second")},
	}, true)
	if err := ExtractNewc(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("expected multiple hard-link data members to be rejected")
	}
}

func TestExtractNewcCreatesEmptyHardLinks(t *testing.T) {
	data := buildNewc(t, []newcTestEntry{
		{name: "empty-a", mode: cpioModeRegular | 0o644, ino: 9, nlink: 2},
		{name: "empty-b", mode: cpioModeRegular | 0o644, ino: 9, nlink: 2},
	}, true)
	dest := t.TempDir()
	if err := ExtractNewc(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractNewc: %v", err)
	}
	a, err := os.Stat(filepath.Join(dest, "empty-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(dest, "empty-b"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) || a.Size() != 0 {
		t.Fatal("empty hard-link identity was not preserved")
	}
}
