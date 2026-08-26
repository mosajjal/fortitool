package diskimage

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateEntryName(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../escape", "dir/file", `dir\\file`, "nul\x00name", strings.Repeat("x", 256)} {
		if err := validateEntryName(name); err == nil {
			t.Errorf("validateEntryName(%q) succeeded", name)
		}
	}
	if err := validateEntryName("normal-name"); err != nil {
		t.Fatalf("normal name rejected: %v", err)
	}
}

func TestSafeExtractSymlinkTarget(t *testing.T) {
	if _, err := safeExtractSymlinkTarget("escape", "../../outside"); err == nil {
		t.Fatal("expected escaping target to fail")
	}
	got, err := safeExtractSymlinkTarget("usr/bin/tool", "/sbin/init")
	if err != nil {
		t.Fatal(err)
	}
	if got != "../../sbin/init" {
		t.Fatalf("rebased absolute target = %q", got)
	}
}

func addFastSymlink(t *testing.T, img []byte, name, target string) {
	t.Helper()
	const inode = uint32(7)
	if len(name) == 0 || len(name) > 255 || len(target) > 60 {
		t.Fatal("invalid synthetic symlink fixture")
	}
	inodeOff := testInodeTblBlock*testBlockSize + int(inode-1)*128
	raw := img[inodeOff : inodeOff+128]
	binary.LittleEndian.PutUint16(raw[0:2], s_IFLNK|0o777)
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(target)))
	copy(raw[40:100], target)

	dir := img[rootDirBlock*testBlockSize : (rootDirBlock+1)*testBlockSize]
	off := 0
	for {
		if off+dirEntryHeaderSize > len(dir) {
			t.Fatal("synthetic root directory has no final record")
		}
		recLen := int(binary.LittleEndian.Uint16(dir[off+4 : off+6]))
		if recLen < dirEntryHeaderSize || off+recLen > len(dir) {
			t.Fatal("synthetic root directory has an invalid record")
		}
		if off+recLen == len(dir) {
			minimum := (dirEntryHeaderSize + int(dir[off+6]) + 3) &^ 3
			newOffset := off + minimum
			newRecordMinimum := (dirEntryHeaderSize + len(name) + 3) &^ 3
			if newOffset+newRecordMinimum > len(dir) {
				t.Fatal("synthetic root directory is full")
			}
			binary.LittleEndian.PutUint16(dir[off+4:off+6], uint16(minimum))
			off = newOffset
			break
		}
		off += recLen
	}
	recLen := len(dir) - off
	binary.LittleEndian.PutUint32(dir[off:off+4], inode)
	binary.LittleEndian.PutUint16(dir[off+4:off+6], uint16(recLen))
	dir[off+6] = byte(len(name))
	dir[off+7] = 7 // EXT2_FT_SYMLINK
	copy(dir[off+8:off+8+len(name)], name)
}

func TestExtractAllWritesSafeTree(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "output")
	if err := fs.ExtractAll(dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "subdir", "nested.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, nestedContent) {
		t.Fatalf("nested output = %q", got)
	}
}

func TestExtractAllSkipsUnreadableFileData(t *testing.T) {
	fs := openWithBlockReadFailure(t, fakeExt2(t), smallFileBlock)
	dest := filepath.Join(t.TempDir(), "output")
	if err := fs.ExtractAll(dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "small.txt")); !os.IsNotExist(err) {
		t.Fatalf("unreadable file was materialised: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "subdir", "nested.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, nestedContent) {
		t.Fatalf("later readable file = %q", got)
	}
}

func TestExtractAllMaterialisesSparseFileLargerThanFilesystem(t *testing.T) {
	img := fakeExt2(t)
	logicalSize := uint32(len(img) + testBlockSize)
	inodeOffset := fixtureInodeOffset(inoSmall)
	binary.LittleEndian.PutUint32(img[inodeOffset+4:inodeOffset+8], logicalSize)
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "output")
	if err := fs.ExtractAll(dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "small.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != int(logicalSize) {
		t.Fatalf("extracted sparse file size = %d, want %d", len(got), logicalSize)
	}
	if !bytes.Equal(got[:len(smallContent)], smallContent) {
		t.Fatalf("extracted sparse file prefix = %q", got[:len(smallContent)])
	}
	if !bytes.Equal(got[len(smallContent):], make([]byte, int(logicalSize)-len(smallContent))) {
		t.Fatal("extracted sparse range contains non-zero data")
	}
}

func TestExtractAllSkipsUnreadableNonDirectoryInode(t *testing.T) {
	img := fakeExt2(t)
	inodeOffset := int64(testInodeTblBlock*testBlockSize + int(inoSmall-1)*128)
	fs, err := OpenAt(failingReaderAt{
		reader:    bytes.NewReader(img),
		failStart: inodeOffset,
		failEnd:   inodeOffset + 128,
	}, int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "output")
	if err := fs.ExtractAll(dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "small.txt")); !os.IsNotExist(err) {
		t.Fatalf("unreadable inode was materialised: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "subdir", "nested.txt")); err != nil {
		t.Fatalf("later readable file was not extracted: %v", err)
	}
}

func TestExtractAllRejectsUnreadableDirectoryInode(t *testing.T) {
	img := fakeExt2(t)
	inodeOffset := int64(testInodeTblBlock*testBlockSize + int(inoSub-1)*128)
	fs, err := OpenAt(failingReaderAt{
		reader:    bytes.NewReader(img),
		failStart: inodeOffset,
		failEnd:   inodeOffset + 128,
	}, int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.ExtractAll(filepath.Join(t.TempDir(), "output")); err == nil {
		t.Fatal("expected an unreadable directory inode to remain fatal")
	}
}

func TestExtractAllRejectsUnreadableLegacyEntryInode(t *testing.T) {
	img := fakeExt2(t)
	binary.LittleEndian.PutUint32(img[testBlockSize+96:testBlockSize+100], 0)
	clearFixtureDirFileTypes(t, img, rootDirBlock)
	clearFixtureDirFileTypes(t, img, subDirBlock)
	inodeOffset := int64(testInodeTblBlock*testBlockSize + int(inoSmall-1)*128)
	fs, err := OpenAt(failingReaderAt{
		reader:    bytes.NewReader(img),
		failStart: inodeOffset,
		failEnd:   inodeOffset + 128,
	}, int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.ExtractAll(filepath.Join(t.TempDir(), "output")); err == nil {
		t.Fatal("expected an unreadable legacy entry without a file type to remain fatal")
	}
}

func TestExtractAllRejectsDirectoryReadFailure(t *testing.T) {
	fs := openWithBlockReadFailure(t, fakeExt2(t), rootDirBlock)
	if err := fs.ExtractAll(filepath.Join(t.TempDir(), "output")); err == nil {
		t.Fatal("expected a directory read failure to remain fatal")
	}
}

func TestExtractAllRebasesAbsoluteSymlink(t *testing.T) {
	img := fakeExt2(t)
	addFastSymlink(t, img, "absolute-link", "/small.txt")
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "output")
	if err := fs.ExtractAll(dest); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(dest, "absolute-link"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "small.txt" {
		t.Fatalf("rebased target = %q", target)
	}
}

func TestExtractAllRebasesRepeatedSymlinkPerPath(t *testing.T) {
	img := fakeExt2(t)
	addFastSymlink(t, img, "root-link", "/small.txt")
	addFixtureDirectoryEntry(t, img, subDirBlock, 7, 7, "deep-link")
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "output")
	if err := fs.ExtractAll(dest); err != nil {
		t.Fatal(err)
	}
	rootTarget, err := os.Readlink(filepath.Join(dest, "root-link"))
	if err != nil {
		t.Fatal(err)
	}
	if rootTarget != "small.txt" {
		t.Fatalf("root symlink target = %q, want %q", rootTarget, "small.txt")
	}
	deepTarget, err := os.Readlink(filepath.Join(dest, "subdir", "deep-link"))
	if err != nil {
		t.Fatal(err)
	}
	if deepTarget != "../small.txt" {
		t.Fatalf("nested symlink target = %q, want %q", deepTarget, "../small.txt")
	}
}

func TestExtractAllRejectsEscapingRelativeSymlink(t *testing.T) {
	img := fakeExt2(t)
	addFastSymlink(t, img, "escape", "../../outside")
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	dest := filepath.Join(parent, "output")
	if err := fs.ExtractAll(dest); err == nil {
		t.Fatal("expected escaping ext symlink to fail")
	}
	if _, err := os.Lstat(filepath.Join(parent, "outside")); !os.IsNotExist(err) {
		t.Fatalf("outside path changed: %v", err)
	}
}

func TestExtractAllRejectsPreExistingSymlinkAncestor(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dest, "subdir")); err != nil {
		t.Fatal(err)
	}
	if err := fs.ExtractAll(dest); err == nil {
		t.Fatal("expected pre-existing ext output symlink to fail")
	}
	if _, err := os.Lstat(filepath.Join(outside, "nested.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside path changed: %v", err)
	}
}

func TestExtractAllRejectsDirectoryInodeCycle(t *testing.T) {
	img := fakeExt2(t)
	dir := img[subDirBlock*testBlockSize : (subDirBlock+1)*testBlockSize]
	nameOffset := bytes.Index(dir, []byte("nested.txt"))
	if nameOffset < dirEntryHeaderSize {
		t.Fatal("synthetic nested directory entry not found")
	}
	header := nameOffset - dirEntryHeaderSize
	binary.LittleEndian.PutUint32(dir[header:header+4], inoRoot)
	dir[header+7] = 2 // EXT2_FT_DIR

	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "output")
	if err := fs.ExtractAll(dest); err == nil {
		t.Fatal("expected repeated directory inode to fail")
	}
	if _, err := os.Lstat(filepath.Join(dest, "subdir", "nested.txt")); !os.IsNotExist(err) {
		t.Fatalf("cyclic directory was materialised: %v", err)
	}
}

func TestExtractAllRejectsSymlinkDestinationRoot(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	outside := t.TempDir()
	dest := filepath.Join(parent, "output")
	if err := os.Symlink(outside, dest); err != nil {
		t.Fatal(err)
	}
	if err := fs.ExtractAll(dest); err == nil {
		t.Fatal("expected symlink destination root to fail")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("outside directory changed: %v", entries)
	}
}

func TestExtractAllPreservesExistingOutput(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	target := filepath.Join(dest, "small.txt")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.ExtractAll(dest); err == nil {
		t.Fatal("expected ext output collision")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("existing output changed to %q", got)
	}
}

func TestReadDirRejectsInvalidEntryNames(t *testing.T) {
	for _, badName := range []string{"bad/name!", `bad\name!`, "nul\x00name!"} {
		t.Run(badName, func(t *testing.T) {
			img := fakeExt2(t)
			dir := img[rootDirBlock*testBlockSize : (rootDirBlock+1)*testBlockSize]
			off := bytes.Index(dir, []byte("small.txt"))
			if off < 0 || len(badName) != len("small.txt") {
				t.Fatal("invalid synthetic directory-name fixture")
			}
			copy(dir[off:off+len(badName)], badName)
			fs, err := Open(img)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fs.ReadDir(""); err == nil {
				t.Fatal("expected invalid ext directory-entry name to fail")
			}
		})
	}
}
