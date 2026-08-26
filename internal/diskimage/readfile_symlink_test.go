package diskimage

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestReadFileFollowsSameDirectorySymlink(t *testing.T) {
	img := fakeExt2(t)
	addFastSymlink(t, img, "required", "./small.txt")
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile("required")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, smallContent) {
		t.Fatalf("ReadFile content = %q, want %q", got, smallContent)
	}
}

func TestReadFileFollowsNestedSameDirectorySymlink(t *testing.T) {
	img := fakeExt2(t)
	addFastSymlink(t, img, "required", "./nested.txt")
	addFixtureDirectoryEntry(t, img, subDirBlock, 7, 7, "required")
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile("subdir/required")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, nestedContent) {
		t.Fatalf("ReadFile content = %q, want %q", got, nestedContent)
	}
}

func TestReadFileRejectsUnsupportedSymlinkTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "empty", target: ""},
		{name: "bare same-directory name", target: "small.txt"},
		{name: "absolute", target: "/small.txt"},
		{name: "parent", target: "../small.txt"},
		{name: "subdirectory", target: "subdir/nested.txt"},
		{name: "collapsed parent", target: "subdir/../small.txt"},
		{name: "trailing slash", target: "small.txt/"},
		{name: "backslash", target: `subdir\\nested.txt`},
		{name: "nul", target: "small.txt\x00ignored"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := fakeExt2(t)
			addFastSymlink(t, img, "required", tt.target)
			fs, err := Open(img)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fs.ReadFile("required"); err == nil || !strings.Contains(err.Error(), "unsupported file symlink target") {
				t.Fatalf("ReadFile error = %v, want unsupported target", err)
			}
		})
	}
}

func TestReadFileRejectsSymlinkChain(t *testing.T) {
	img := fakeExt2(t)
	addFastSymlink(t, img, "required", "./small.txt")
	inodeOffset := fixtureInodeOffset(inoSmall)
	raw := img[inodeOffset : inodeOffset+128]
	clear(raw)
	binary.LittleEndian.PutUint16(raw[0:2], s_IFLNK|0o777)
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len("big.txt")))
	copy(raw[40:100], "big.txt")
	clearFixtureDirFileTypes(t, img, rootDirBlock)
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile("required"); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("ReadFile error = %v, want non-regular target", err)
	}
}

func TestReadFileRejectsNonRegularSymlinkTarget(t *testing.T) {
	tests := []struct {
		name string
		mode uint16
	}{
		{name: "directory", mode: s_IFDIR | 0o755},
		{name: "block device", mode: s_IFBLK | 0o600},
		{name: "character device", mode: s_IFCHR | 0o600},
		{name: "fifo", mode: s_IFIFO | 0o600},
		{name: "socket", mode: s_IFSOCK | 0o600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := fakeExt2(t)
			addFastSymlink(t, img, "required", "./small.txt")
			inodeOffset := fixtureInodeOffset(inoSmall)
			binary.LittleEndian.PutUint16(img[inodeOffset:inodeOffset+2], tt.mode)
			clearFixtureDirFileTypes(t, img, rootDirBlock)
			fs, err := Open(img)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fs.ReadFile("required"); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
				t.Fatalf("ReadFile error = %v, want non-regular target", err)
			}
		})
	}
}
