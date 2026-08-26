package diskimage

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestReadExtentMappedFileRejectsMalformedTrees(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
		want   string
	}{
		{
			name: "flag without filesystem feature",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[extBlockSize+96:extBlockSize+100], extFeatureIncompatFiletype)
			},
			want: "extent flag without filesystem extent feature",
		},
		{
			name: "invalid root magic",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint16(img[extentFixtureInodeOffset()+40:extentFixtureInodeOffset()+42], 0)
			},
			want: "invalid root magic",
		},
		{
			name: "inline data flag",
			mutate: func(img []byte) {
				off := extentFixtureInodeOffset()
				binary.LittleEndian.PutUint32(img[off+32:off+36], inodeFlagExtents|inodeFlagInlineData)
			},
			want: "unsupported inline data",
		},
		{
			name: "excessive depth",
			mutate: func(img []byte) {
				root := extentFixtureInodeOffset() + 40
				binary.LittleEndian.PutUint16(img[root+6:root+8], maxExtentDepth+1)
			},
			want: "exceeds supported maximum",
		},
		{
			name: "entries beyond maximum",
			mutate: func(img []byte) {
				root := extentFixtureInodeOffset() + 40
				binary.LittleEndian.PutUint16(img[root+2:root+4], 5)
			},
			want: "corrupt extent header",
		},
		{
			name: "child magic",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint16(img[6*extBlockSize:6*extBlockSize+2], 0)
			},
			want: "corrupt extent header magic",
		},
		{
			name: "child depth",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint16(img[6*extBlockSize+6:6*extBlockSize+8], 1)
			},
			want: "corrupt extent depth",
		},
		{
			name: "extent beyond inode size",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[6*extBlockSize+24:6*extBlockSize+28], 5)
			},
			want: "overlapping or out-of-range extent",
		},
		{
			name: "overlapping leaves",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[6*extBlockSize+24:6*extBlockSize+28], 1)
			},
			want: "overlapping or out-of-range extent",
		},
		{
			name: "zero length",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint16(img[6*extBlockSize+16:6*extBlockSize+18], 0)
			},
			want: "zero-length extent",
		},
		{
			name: "physical range",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[6*extBlockSize+32:6*extBlockSize+36], 12)
			},
			want: "outside filesystem blocks",
		},
		{
			name: "48-bit physical address",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint16(img[6*extBlockSize+18:6*extBlockSize+20], 1)
			},
			want: "48-bit extent block address",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			img := buildExtentFS(t)
			tc.mutate(img)
			fs, err := Open(img)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fs.ReadFile("sparse.data"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadFile error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestReadExtentMappedFileRejectsTreeCycle(t *testing.T) {
	img := buildExtentFS(t)
	root := extentFixtureInodeOffset() + 40
	binary.LittleEndian.PutUint16(img[root+6:root+8], 2)
	node := img[6*extBlockSize : 7*extBlockSize]
	clear(node)
	binary.LittleEndian.PutUint16(node[0:2], extentMagic)
	binary.LittleEndian.PutUint16(node[2:4], 1)
	binary.LittleEndian.PutUint16(node[4:6], uint16((len(node)-12)/12))
	binary.LittleEndian.PutUint16(node[6:8], 1)
	binary.LittleEndian.PutUint32(node[16:20], 6)

	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile("sparse.data"); err == nil || !strings.Contains(err.Error(), "extent tree reuses block 6") {
		t.Fatalf("ReadFile error = %v, want extent-cycle rejection", err)
	}
}

func TestReadExtentMappedFileRejectsReusedChild(t *testing.T) {
	img := buildExtentFS(t)
	root := extentFixtureInodeOffset() + 40
	binary.LittleEndian.PutUint16(img[root+2:root+4], 2)
	binary.LittleEndian.PutUint32(img[root+24:root+28], 2)
	binary.LittleEndian.PutUint32(img[root+28:root+32], 6)
	leaf := img[6*extBlockSize : 7*extBlockSize]
	binary.LittleEndian.PutUint16(leaf[2:4], 1)
	binary.LittleEndian.PutUint16(leaf[16:18], 1)

	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile("sparse.data"); err == nil || !strings.Contains(err.Error(), "extent tree reuses block 6") {
		t.Fatalf("ReadFile error = %v, want repeated-child rejection", err)
	}
}

func TestReadExtentMappedFilePreservesUninitialisedExtent(t *testing.T) {
	img := buildExtentFS(t)
	binary.LittleEndian.PutUint16(img[6*extBlockSize+28:6*extBlockSize+30], 0x8001)
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile("sparse.data")
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(sparseContent)
	clear(want[4*extBlockSize:])
	if !bytes.Equal(got, want) {
		t.Fatal("uninitialised extent was not returned as a sparse hole")
	}
}

func TestReadExtentMappedFileSupportsLogicalSizeBeyondFilesystem(t *testing.T) {
	img := buildExtentFS(t)
	logicalSize := uint32(len(img) + extBlockSize)
	binary.LittleEndian.PutUint32(img[extentFixtureInodeOffset()+4:extentFixtureInodeOffset()+8], logicalSize)
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile("sparse.data")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != int(logicalSize) {
		t.Fatalf("sparse file size = %d, want %d", len(got), logicalSize)
	}
	if !bytes.Equal(got[:len(sparseContent)], sparseContent) {
		t.Fatal("mapped sparse-file content changed")
	}
	if !bytes.Equal(got[len(sparseContent):], make([]byte, int(logicalSize)-len(sparseContent))) {
		t.Fatal("trailing sparse range contains non-zero data")
	}
}

func extentFixtureInodeOffset() int {
	return 3*extBlockSize + 2*defaultInodeSize
}
