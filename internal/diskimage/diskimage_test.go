package diskimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// fakeExt2 builds a minimal, single-block-group ext2 image by hand,
// exercising the same on-disk structures the real firmware partition
// uses (classic 32-byte group descriptor, 128-byte dynamic-revision inodes,
// direct + single-indirect block mapping) without needing any real,
// copyrighted firmware data.
//
// Block layout (1024-byte blocks):
//
//	0       unused (boot block)
//	1       superblock
//	2       block group descriptor table
//	3-6     inode table (32 inodes * 128 bytes = 4 blocks)
//	7       root dir data (".", "..", "small.txt", "big.txt", "subdir")
//	8       subdir data (".", "..", "nested.txt")
//	9       small.txt data
//	10      nested.txt data
//	11-22   big.txt direct data blocks (12 blocks)
//	23      big.txt single-indirect pointer block -> {24, 25}
//	24-25   big.txt indirect data blocks
const (
	testBlockSize        = 1024
	testInodesPerGrp     = 32
	testBlocksPerGrp     = 30
	testInodeTblBlock    = 3
	testInodeBitmapBlock = 26
	rootDirBlock         = 7
	subDirBlock          = 8
	smallFileBlock       = 9
	nestedFileBlock      = 10
	bigFileFirstBlock    = 11
	bigFileIndirBlock    = 23
)

const (
	inoRoot   = 2
	inoSub    = 3
	inoSmall  = 4
	inoNested = 5
	inoBig    = 6
)

var (
	smallContent  = []byte("hello ext2 world")
	nestedContent = []byte("nested file content")
)

func fakeExt2(t testing.TB) []byte {
	t.Helper()
	totalBlocks := 27
	img := make([]byte, totalBlocks*testBlockSize)

	block := func(n int) []byte { return img[n*testBlockSize : (n+1)*testBlockSize] }
	le32 := binary.LittleEndian.PutUint32
	le16 := binary.LittleEndian.PutUint16

	// superblock (block 1, offset 1024 in the image)
	sb := block(1)
	le32(sb[0:4], testInodesPerGrp)    // s_inodes_count
	le32(sb[4:8], uint32(totalBlocks)) // s_blocks_count
	le32(sb[20:24], 1)                 // s_first_data_block
	le32(sb[24:28], 0)                 // s_log_block_size -> 1024<<0
	le32(sb[32:36], testBlocksPerGrp)  // s_blocks_per_group
	le32(sb[40:44], testInodesPerGrp)  // s_inodes_per_group
	le32(sb[76:80], 1)                 // s_rev_level = DYNAMIC_REV
	le16(sb[56:58], 0xEF53)            // s_magic
	le16(sb[88:90], defaultInodeSize)  // s_inode_size
	le32(sb[96:100], extFeatureIncompatFiletype)

	// block group descriptor table (block 2)
	gdt := block(2)
	le32(gdt[0:4], 0) // bg_block_bitmap (unused by our reader)
	le32(gdt[4:8], testInodeBitmapBlock)
	le32(gdt[8:12], testInodeTblBlock) // bg_inode_table
	block(testInodeBitmapBlock)[0] = 0x7f

	writeInode := func(num uint32, mode uint16, size uint32, blocks []uint32) {
		off := (testInodeTblBlock * testBlockSize) + int(num-1)*128
		raw := img[off : off+128]
		le16(raw[0:2], mode)
		le32(raw[4:8], size)
		for i, b := range blocks {
			le32(raw[40+i*4:44+i*4], b)
		}
	}

	const (
		sIFDIR = 0o040000
		sIFREG = 0o100000
	)

	writeInode(inoRoot, sIFDIR|0o755, testBlockSize, []uint32{rootDirBlock})
	writeInode(inoSub, sIFDIR|0o755, testBlockSize, []uint32{subDirBlock})
	writeInode(inoSmall, sIFREG|0o644, uint32(len(smallContent)), []uint32{smallFileBlock})
	writeInode(inoNested, sIFREG|0o644, uint32(len(nestedContent)), []uint32{nestedFileBlock})

	bigContent := bytes.Repeat([]byte("BIGFILEDATA-"), (14*testBlockSize)/12+1)[:14*testBlockSize]
	bigBlocks := make([]uint32, 15) // 12 direct + iBlockSingle + 2 unused indirect/triple slots
	for i := 0; i < 12; i++ {
		bigBlocks[i] = uint32(bigFileFirstBlock + i)
	}
	bigBlocks[12] = bigFileIndirBlock // single-indirect
	writeInode(inoBig, sIFREG|0o644, uint32(len(bigContent)), bigBlocks)

	writeDirBlock := func(blockNum int, entries []dirEnt) {
		buf := block(blockNum)
		off := 0
		for i, e := range entries {
			recLen := (dirEntryHeaderSize + len(e.name) + 3) &^ 3
			if i == len(entries)-1 {
				recLen = len(buf) - off
			}
			if recLen < dirEntryHeaderSize+len(e.name) || off+recLen > len(buf) {
				t.Fatal("synthetic directory entries exceed their block")
			}
			le32(buf[off:off+4], e.inode)
			le16(buf[off+4:off+6], uint16(recLen))
			buf[off+6] = byte(len(e.name))
			buf[off+7] = e.fileType
			copy(buf[off+8:off+8+len(e.name)], e.name)
			off += recLen
		}
	}

	const (
		ftDir = 2
		ftReg = 1
	)
	writeDirBlock(rootDirBlock, []dirEnt{
		{inoRoot, ftDir, "."},
		{inoRoot, ftDir, ".."},
		{inoSmall, ftReg, "small.txt"},
		{inoBig, ftReg, "big.txt"},
		{inoSub, ftDir, "subdir"},
	})
	writeDirBlock(subDirBlock, []dirEnt{
		{inoSub, ftDir, "."},
		{inoRoot, ftDir, ".."},
		{inoNested, ftReg, "nested.txt"},
	})

	copy(block(smallFileBlock), smallContent)
	copy(block(nestedFileBlock), nestedContent)
	for i := 0; i < 12; i++ {
		copy(block(bigFileFirstBlock+i), bigContent[i*testBlockSize:(i+1)*testBlockSize])
	}
	indirPtrs := block(bigFileIndirBlock)
	le32(indirPtrs[0:4], 24)
	le32(indirPtrs[4:8], 25)
	// remaining pointer slots in this block are left zero -- FS.readInodeData
	// must never touch them, since size caps the walk at exactly 14 blocks
	// (12 direct + 2 indirect); this is exactly the bug this repo's real
	// firmware run hit (see internal/diskimage doc comment history).
	copy(block(24), bigContent[12*testBlockSize:13*testBlockSize])
	copy(block(25), bigContent[13*testBlockSize:14*testBlockSize])

	return img
}

type dirEnt struct {
	inode    uint32
	fileType byte
	name     string
}

func TestOpenAndReadDir(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entries, err := fs.ReadDir("")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	want := map[string]bool{"small.txt": false, "big.txt": false, "subdir": true}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name] = e.IsDir
	}
	for name, isDir := range want {
		gotDir, ok := got[name]
		if !ok {
			t.Fatalf("missing root entry %q (got %v)", name, got)
		}
		if gotDir != isDir {
			t.Fatalf("%q IsDir = %v, want %v", name, gotDir, isDir)
		}
	}
}

func TestReadFileSmall(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile("small.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, smallContent) {
		t.Fatalf("got %q want %q", got, smallContent)
	}
}

func TestReadFileNested(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile("subdir/nested.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, nestedContent) {
		t.Fatalf("got %q want %q", got, nestedContent)
	}
}

// TestReadFileSingleIndirect proves the single-indirect block walk is both
// correct AND bounded -- it must recover all 14 blocks of content and must
// not choke on the unused, unzeroed-in-principle pointer slots beyond the
// two real ones in the indirect block.
func TestReadFileSingleIndirect(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile("big.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	want := bytes.Repeat([]byte("BIGFILEDATA-"), (14*testBlockSize)/12+1)[:14*testBlockSize]
	if !bytes.Equal(got, want) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestReadFileNotFound(t *testing.T) {
	fs, err := Open(fakeExt2(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile("does-not-exist.txt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file error = %v, want ErrNotFound", err)
	}
}

func TestOpenRejectsBadMagic(t *testing.T) {
	junk := make([]byte, 4096)
	if _, err := Open(junk); err == nil {
		t.Fatal("expected an error for a non-ext2 image")
	}
}

var errSyntheticBlockRead = errors.New("synthetic block read failure")

type failingReaderAt struct {
	reader    *bytes.Reader
	failStart int64
	failEnd   int64
}

func (r failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < r.failEnd && off+int64(len(p)) > r.failStart {
		return 0, errSyntheticBlockRead
	}
	return r.reader.ReadAt(p, off)
}

func openWithBlockReadFailure(t *testing.T, img []byte, block int) *FS {
	t.Helper()
	start := int64(block * testBlockSize)
	fs, err := OpenAt(failingReaderAt{
		reader:    bytes.NewReader(img),
		failStart: start,
		failEnd:   start + testBlockSize,
	}, int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestReadFilePropagatesBlockReadFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block int
		path  string
	}{
		{name: "directory data", block: rootDirBlock, path: "small.txt"},
		{name: "direct data", block: smallFileBlock, path: "small.txt"},
		{name: "single-indirect table", block: bigFileIndirBlock, path: "big.txt"},
		{name: "single-indirect data", block: 24, path: "big.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := openWithBlockReadFailure(t, fakeExt2(t), tc.block)
			if _, err := fs.ReadFile(tc.path); !errors.Is(err, errSyntheticBlockRead) {
				t.Fatalf("ReadFile error = %v, want synthetic block read failure", err)
			}
		})
	}
}

func TestReadInodeDataPropagatesDoubleIndirectReadFailures(t *testing.T) {
	const (
		doubleTableBlock = 27
		childTableBlock  = 28
		doubleDataBlock  = 29
		totalBlocks      = 300
	)
	for _, block := range []int{doubleTableBlock, childTableBlock, doubleDataBlock} {
		t.Run(fmt.Sprintf("block-%d", block), func(t *testing.T) {
			base := fakeExt2(t)
			img := make([]byte, totalBlocks*testBlockSize)
			copy(img, base)
			binary.LittleEndian.PutUint32(img[testBlockSize+4:testBlockSize+8], totalBlocks)
			binary.LittleEndian.PutUint32(img[doubleTableBlock*testBlockSize:doubleTableBlock*testBlockSize+4], childTableBlock)
			binary.LittleEndian.PutUint32(img[childTableBlock*testBlockSize:childTableBlock*testBlockSize+4], doubleDataBlock)

			fs := openWithBlockReadFailure(t, img, block)
			in := &inode{sizeLo: uint32((nDirect + testBlockSize/4 + 1) * testBlockSize)}
			in.block[iBlockDouble] = doubleTableBlock
			if _, err := fs.readInodeDataIndirect(99, in); !errors.Is(err, errSyntheticBlockRead) {
				t.Fatalf("readInodeDataIndirect error = %v, want synthetic block read failure", err)
			}
		})
	}
}

func TestReadFileRejectsBlockOutsideFilesystem(t *testing.T) {
	img := fakeExt2(t)
	inodeOff := testInodeTblBlock*testBlockSize + int(inoSmall-1)*128
	binary.LittleEndian.PutUint32(img[inodeOff+40:inodeOff+44], uint32(len(img)/testBlockSize))
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadFile("small.txt"); err == nil {
		t.Fatal("expected an out-of-filesystem block pointer to fail")
	}
}

func TestReadFilePreservesExplicitSparseHole(t *testing.T) {
	img := fakeExt2(t)
	inodeOff := testInodeTblBlock*testBlockSize + int(inoSmall-1)*128
	binary.LittleEndian.PutUint32(img[inodeOff+40:inodeOff+44], 0)
	fs, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile("small.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, make([]byte, len(smallContent))) {
		t.Fatalf("sparse file data = %x", got)
	}
}

func TestReadFileRejectsZeroLengthDirectoryRecord(t *testing.T) {
	for _, path := range []string{"small.txt", "optional.bin"} {
		t.Run(path, func(t *testing.T) {
			img := fakeExt2(t)
			dir := img[rootDirBlock*testBlockSize : (rootDirBlock+1)*testBlockSize]
			secondRecord := int(binary.LittleEndian.Uint16(dir[4:6]))
			binary.LittleEndian.PutUint16(dir[secondRecord+4:secondRecord+6], 0)
			fs, err := Open(img)
			if err != nil {
				t.Fatal(err)
			}
			_, err = fs.ReadFile(path)
			if err == nil {
				t.Fatal("expected a zero-length directory record to fail")
			}
			if errors.Is(err, ErrNotFound) {
				t.Fatalf("directory corruption was reported as optional absence: %v", err)
			}
		})
	}
}
