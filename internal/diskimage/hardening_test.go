package diskimage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenPreservesSupportedExt2AndExt3Layouts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "ext2 file types"},
		{
			name: "legacy ext2 directory entries",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+76:testBlockSize+80], 0)
				binary.LittleEndian.PutUint16(img[testBlockSize+88:testBlockSize+90], 0)
				binary.LittleEndian.PutUint32(img[testBlockSize+96:testBlockSize+100], 0)
				clearFixtureDirFileTypes(t, img, rootDirBlock)
				clearFixtureDirFileTypes(t, img, subDirBlock)
			},
		},
		{
			name: "clean ext3 journal feature",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+92:testBlockSize+96], 0x0004)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			img := fakeExt2(t)
			if tc.mutate != nil {
				tc.mutate(img)
			}
			fs, err := Open(img)
			if err != nil {
				t.Fatal(err)
			}
			got, err := fs.ReadFile("subdir/nested.txt")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, nestedContent) {
				t.Fatalf("nested content = %q", got)
			}
		})
	}
}

func TestOpenSupports64KiBDirectoryRecords(t *testing.T) {
	const (
		blockSize  = 65536
		blockCount = 5
	)
	for _, encodedLength := range []uint16{0, ^uint16(0)} {
		t.Run(fmt.Sprintf("record length 0x%04x", encodedLength), func(t *testing.T) {
			img := make([]byte, blockSize*blockCount)
			sb := img[superblockOffset : superblockOffset+superblockSize]
			binary.LittleEndian.PutUint32(sb[0:4], 2)
			binary.LittleEndian.PutUint32(sb[4:8], blockCount)
			binary.LittleEndian.PutUint32(sb[20:24], 0)
			binary.LittleEndian.PutUint32(sb[24:28], 6)
			binary.LittleEndian.PutUint32(sb[32:36], blockCount)
			binary.LittleEndian.PutUint32(sb[40:44], 2)
			binary.LittleEndian.PutUint16(sb[56:58], ext2Magic)
			binary.LittleEndian.PutUint32(sb[76:80], 1)
			binary.LittleEndian.PutUint16(sb[88:90], defaultInodeSize)
			binary.LittleEndian.PutUint32(sb[96:100], extFeatureIncompatFiletype)
			gdt := img[blockSize : blockSize+bgDescSize]
			binary.LittleEndian.PutUint32(gdt[4:8], 3)
			binary.LittleEndian.PutUint32(gdt[8:12], 2)
			img[3*blockSize] = 0x03
			root := img[2*blockSize+defaultInodeSize : 2*blockSize+2*defaultInodeSize]
			binary.LittleEndian.PutUint16(root[0:2], s_IFDIR|0o755)
			binary.LittleEndian.PutUint32(root[4:8], blockSize)
			binary.LittleEndian.PutUint32(root[40:44], 4)
			dir := img[4*blockSize : 5*blockSize]
			binary.LittleEndian.PutUint32(dir[0:4], rootInode)
			binary.LittleEndian.PutUint16(dir[4:6], encodedLength)
			dir[6] = 1
			dir[7] = 2
			dir[8] = '.'

			fs, err := Open(img)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := fs.ReadDir("")
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("ReadDir returned %d non-dot entries", len(entries))
			}
		})
	}
}

func TestOpenRejectsUnsupportedFeaturesAndInvalidGeometry(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
		want   string
	}{
		{
			name: "revision 0 feature flags",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+76:testBlockSize+80], 0)
				binary.LittleEndian.PutUint16(img[testBlockSize+88:testBlockSize+90], 0)
			},
			want: "revision 0 filesystem has unsupported feature flags",
		},
		{
			name: "unknown revision",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+76:testBlockSize+80], maxRevisionLevel+1)
			},
			want: "unsupported filesystem revision",
		},
		{
			name: "unknown incompatible feature",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+96:testBlockSize+100], extFeatureIncompatFiletype|0x80000000)
			},
			want: "unsupported incompatible filesystem features",
		},
		{
			name: "journal recovery required",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+96:testBlockSize+100], extFeatureIncompatFiletype|0x0004)
			},
			want: "unsupported incompatible filesystem features",
		},
		{
			name: "bigalloc",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+100:testBlockSize+104], extFeatureROCompatBigalloc)
			},
			want: "unsupported bigalloc",
		},
		{
			name: "block size exponent",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+24:testBlockSize+28], 32)
			},
			want: "block-size exponent",
		},
		{
			name: "first data block",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+20:testBlockSize+24], 0)
			},
			want: "first data block",
		},
		{
			name: "zero blocks per group",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+32:testBlockSize+36], 0)
			},
			want: "invalid zero or undersized",
		},
		{
			name: "bitmap capacity",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+32:testBlockSize+36], testBlockSize*8+1)
			},
			want: "exceeds bitmap capacity",
		},
		{
			name: "inode group capacity",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize:testBlockSize+4], testInodesPerGrp+1)
			},
			want: "exceeds group capacity",
		},
		{
			name: "dynamic inode size",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+76:testBlockSize+80], 1)
				binary.LittleEndian.PutUint16(img[testBlockSize+88:testBlockSize+90], 192)
			},
			want: "invalid inode size",
		},
		{
			name: "uninitialised inode metadata",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint16(img[2*testBlockSize+18:2*testBlockSize+20], extGroupFlagInodeUninit)
			},
			want: "inode bitmap and table are uninitialised",
		},
		{
			name: "inode table overlaps primary metadata",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[2*testBlockSize+8:2*testBlockSize+12], 2)
			},
			want: "overlaps the primary superblock or descriptor table",
		},
		{
			name: "inode bitmap overlaps table",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[2*testBlockSize+4:2*testBlockSize+8], testInodeTblBlock)
			},
			want: "inode bitmap overlaps inode table",
		},
		{
			name: "inode table past filesystem",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[2*testBlockSize+8:2*testBlockSize+12], 25)
			},
			want: "inode table runs past filesystem",
		},
		{
			name: "partial final group reserves full inode table",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize:testBlockSize+4], rootInode)
				binary.LittleEndian.PutUint32(img[2*testBlockSize+8:2*testBlockSize+12], 25)
				copy(img[25*testBlockSize+defaultInodeSize:25*testBlockSize+2*defaultInodeSize], img[fixtureInodeOffset(rootInode):fixtureInodeOffset(rootInode)+defaultInodeSize])
			},
			want: "inode table runs past filesystem",
		},
		{
			name: "overflow-sized block count",
			mutate: func(img []byte) {
				binary.LittleEndian.PutUint32(img[testBlockSize+4:testBlockSize+8], ^uint32(0))
				binary.LittleEndian.PutUint32(img[testBlockSize+32:testBlockSize+36], 2)
			},
			want: "filesystem geometry requires",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			img := fakeExt2(t)
			tc.mutate(img)
			if _, err := Open(img); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Open error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestOpenRejectsUnallocatedRootInode(t *testing.T) {
	img := fakeExt2(t)
	img[testInodeBitmapBlock*testBlockSize] &^= 1 << (rootInode - 1)
	if _, err := Open(img); err == nil || !strings.Contains(err.Error(), "inode 2 is not allocated") {
		t.Fatalf("Open error = %v, want unallocated root inode", err)
	}
}

func TestReadDirRejectsInvalidReferencedInodes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte, int)
		want   string
	}{
		{
			name: "unallocated",
			mutate: func(img []byte, _ int) {
				img[testInodeBitmapBlock*testBlockSize] &^= 1 << (inoSmall - 1)
			},
			want: "inode 4 is not allocated",
		},
		{
			name: "past inode count",
			mutate: func(img []byte, entry int) {
				binary.LittleEndian.PutUint32(img[entry:entry+4], testInodesPerGrp+1)
			},
			want: "outside inode count",
		},
		{
			name: "file type mismatch",
			mutate: func(img []byte, entry int) {
				img[entry+7] = 2
			},
			want: "inconsistent file type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			img := fakeExt2(t)
			entry := fixtureDirEntryOffset(t, img, rootDirBlock, "small.txt")
			tc.mutate(img, entry)
			fs, err := Open(img)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fs.ReadDir(""); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadDir error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestReadDirRejectsUnsupportedHighFileSize(t *testing.T) {
	img := fakeExt2(t)
	off := fixtureInodeOffset(inoSmall)
	binary.LittleEndian.PutUint32(img[off+108:off+112], 1)
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadDir(""); err == nil || !strings.Contains(err.Error(), "unsupported 64-bit file size") {
		t.Fatalf("ReadDir error = %v, want high-size rejection", err)
	}
}

func TestReadDirBoundsDirectoryMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		size uint32
		want string
	}{
		{name: "resource limit", size: maxDirectorySize + 1, want: "exceeds limit"},
		{name: "partial block", size: testBlockSize - 1, want: "invalid size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := fakeExt2(t)
			off := fixtureInodeOffset(rootInode)
			binary.LittleEndian.PutUint32(img[off+4:off+8], tc.size)
			fs, err := Open(img)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fs.ReadDir(""); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadDir error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestResolveRejectsDirectoryCycle(t *testing.T) {
	img := fakeExt2(t)
	entry := fixtureDirEntryOffset(t, img, subDirBlock, "nested.txt")
	binary.LittleEndian.PutUint32(img[entry:entry+4], rootInode)
	img[entry+7] = 2
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadDir("subdir/nested.txt"); err == nil || !strings.Contains(err.Error(), "reuses directory inode") {
		t.Fatalf("ReadDir error = %v, want directory-cycle rejection", err)
	}
}

func TestResolveBoundsPathComponents(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	path := strings.Repeat("component/", testInodesPerGrp+1)
	if _, err := fs.ReadFile(path); err == nil || !strings.Contains(err.Error(), "traversal limit") {
		t.Fatalf("ReadFile error = %v, want traversal limit", err)
	}
}

func TestExtractTraversalStateBoundsWork(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.extractDir("", "", rootInode, nil, &extractState{}, maxDirectoryDepth+1); err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("extractDir depth error = %v", err)
	}
	if err := fs.extractDir("", "", rootInode, nil, &extractState{entries: maxDirectoryEntries}, 0); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("extractDir entry error = %v", err)
	}
	if err := fs.extractDir("", "", rootInode, nil, &extractState{records: maxDirectoryEntries}, 0); err == nil || !strings.Contains(err.Error(), "record limit") {
		t.Fatalf("extractDir record error = %v", err)
	}
	if err := fs.extractDir("", "", rootInode, nil, &extractState{directoryBytes: maxDirectoryTreeBytes}, 0); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("extractDir directory-byte error = %v", err)
	}
}

func TestExtractAllReadsEachDirectoryOnce(t *testing.T) {
	img := fakeExt2(t)
	addFixtureDirectoryEntry(t, img, rootDirBlock, inoSmall, 1, "small-alias")
	reader := &blockReadCountingReaderAt{
		reader: bytes.NewReader(img),
		counts: make(map[int]int),
	}
	fs, err := OpenAt(reader, int64(reader.reader.Size()))
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := fs.ExtractAll(dest); err != nil {
		t.Fatal(err)
	}
	for _, block := range []int{rootDirBlock, subDirBlock} {
		if got := reader.counts[block]; got != 1 {
			t.Fatalf("directory block %d read %d times, want once", block, got)
		}
	}
	if got := reader.counts[smallFileBlock]; got != 1 {
		t.Fatalf("hard-linked data block read %d times, want once", got)
	}
	original, err := os.Stat(filepath.Join(dest, "small.txt"))
	if err != nil {
		t.Fatal(err)
	}
	alias, err := os.Stat(filepath.Join(dest, "small-alias"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(original, alias) {
		t.Fatal("repeated inode was not preserved as a hard link")
	}
}

func TestDirectoryRecordBudgetCountsDeletedEntries(t *testing.T) {
	img := fakeExt2(t)
	block := img[rootDirBlock*testBlockSize : (rootDirBlock+1)*testBlockSize]
	for off := 0; off < len(block); {
		recLen := int(binary.LittleEndian.Uint16(block[off+4 : off+6]))
		binary.LittleEndian.PutUint32(block[off:off+4], 0)
		off += recLen
	}
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	budget := uint64(maxDirectoryEntries - 1)
	if _, err := fs.readDirEntriesBudget(rootInode, &budget, nil); err == nil || !strings.Contains(err.Error(), "record limit") {
		t.Fatalf("readDirEntriesBudget error = %v, want deleted-record budget", err)
	}
}

func TestReadSymlinkDataBoundsTarget(t *testing.T) {
	fs := &FS{}
	if _, err := fs.readSymlinkData(7, &inode{sizeLo: maxSymlinkSize + 1}); err == nil || !strings.Contains(err.Error(), "symlink inode 7") {
		t.Fatalf("readSymlinkData error = %v, want size limit", err)
	}
}

type blockReadCountingReaderAt struct {
	reader *bytes.Reader
	counts map[int]int
}

func addFixtureDirectoryEntry(t testing.TB, img []byte, blockNum int, inode uint32, fileType byte, name string) {
	t.Helper()
	block := img[blockNum*testBlockSize : (blockNum+1)*testBlockSize]
	off := 0
	for {
		recLen := int(binary.LittleEndian.Uint16(block[off+4 : off+6]))
		if recLen < dirEntryHeaderSize || off+recLen > len(block) {
			t.Fatal("invalid synthetic directory record")
		}
		if off+recLen == len(block) {
			minimum := (dirEntryHeaderSize + int(block[off+6]) + 3) &^ 3
			newOffset := off + minimum
			if newOffset+dirEntryHeaderSize+len(name) > len(block) {
				t.Fatal("synthetic directory block is full")
			}
			binary.LittleEndian.PutUint16(block[off+4:off+6], uint16(minimum))
			off = newOffset
			break
		}
		off += recLen
	}
	binary.LittleEndian.PutUint32(block[off:off+4], inode)
	binary.LittleEndian.PutUint16(block[off+4:off+6], uint16(len(block)-off))
	block[off+6] = byte(len(name))
	block[off+7] = fileType
	copy(block[off+dirEntryHeaderSize:], name)
}

func (r *blockReadCountingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	startBlock := int(off) / testBlockSize
	endBlock := int(off+int64(len(p))-1) / testBlockSize
	for block := startBlock; block <= endBlock; block++ {
		r.counts[block]++
	}
	return r.reader.ReadAt(p, off)
}

func TestOverflowHelpersAndSources(t *testing.T) {
	if _, ok := checkedAdd(^uint64(0), 1); ok {
		t.Fatal("checkedAdd accepted overflow")
	}
	if _, ok := checkedMul(^uint64(0), 2); ok {
		t.Fatal("checkedMul accepted overflow")
	}
	if rangeWithin(^uint64(0), 1, ^uint64(0)) {
		t.Fatal("rangeWithin accepted an overflowing range")
	}
	if err := (sliceSource{data: []byte{1}}).at(make([]byte, 1), int64(^uint64(0)>>1)); err == nil {
		t.Fatal("sliceSource accepted an overflowing offset")
	}
}

func FuzzExtMetadataDoesNotPanic(f *testing.F) {
	seed := fakeExt2(f)
	f.Add(seed)
	f.Add(buildExtentFS(f))
	for _, mutate := range []func([]byte){
		func(img []byte) { binary.LittleEndian.PutUint32(img[testBlockSize+24:testBlockSize+28], ^uint32(0)) },
		func(img []byte) { binary.LittleEndian.PutUint32(img[testBlockSize+4:testBlockSize+8], ^uint32(0)) },
		func(img []byte) { binary.LittleEndian.PutUint32(img[2*testBlockSize+8:2*testBlockSize+12], ^uint32(0)) },
	} {
		candidate := bytes.Clone(seed)
		mutate(candidate)
		f.Add(candidate)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		fs, err := Open(data)
		if err != nil {
			return
		}
		_, _ = fs.ReadDir("")
		_, _ = fs.ReadFile("small.txt")
		_, _ = fs.ReadFile("sparse.data")
	})
}

func fixtureInodeOffset(num uint32) int {
	return testInodeTblBlock*testBlockSize + int(num-1)*defaultInodeSize
}

func fixtureDirEntryOffset(t testing.TB, img []byte, blockNum int, name string) int {
	t.Helper()
	base := blockNum * testBlockSize
	block := img[base : base+testBlockSize]
	for off := 0; off+dirEntryHeaderSize <= len(block); {
		recLen := int(binary.LittleEndian.Uint16(block[off+4 : off+6]))
		if recLen < dirEntryHeaderSize || off+recLen > len(block) {
			t.Fatalf("invalid directory fixture at offset %d", off)
		}
		nameLen := int(block[off+6])
		if string(block[off+dirEntryHeaderSize:off+dirEntryHeaderSize+nameLen]) == name {
			return base + off
		}
		off += recLen
	}
	t.Fatalf("directory fixture entry %q not found", name)
	return 0
}

func clearFixtureDirFileTypes(t testing.TB, img []byte, blockNum int) {
	t.Helper()
	base := blockNum * testBlockSize
	block := img[base : base+testBlockSize]
	for off := 0; off+dirEntryHeaderSize <= len(block); {
		recLen := int(binary.LittleEndian.Uint16(block[off+4 : off+6]))
		if recLen < dirEntryHeaderSize || off+recLen > len(block) {
			t.Fatalf("invalid directory fixture at offset %d", off)
		}
		block[off+7] = 0
		off += recLen
	}
}
