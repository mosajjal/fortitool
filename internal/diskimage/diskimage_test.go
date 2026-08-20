package diskimage

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// fakeExt2 builds a minimal, single-block-group ext2 image by hand,
// exercising the same on-disk structures the real firmware partition
// uses (classic 32-byte group descriptor, 128-byte GOOD_OLD_REV inodes,
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
	testBlockSize     = 1024
	testInodesPerGrp  = 32
	testBlocksPerGrp  = 30
	testInodeTblBlock = 3
	rootDirBlock      = 7
	subDirBlock       = 8
	smallFileBlock    = 9
	nestedFileBlock   = 10
	bigFileFirstBlock = 11
	bigFileIndirBlock = 23
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

func fakeExt2(t *testing.T) []byte {
	t.Helper()
	totalBlocks := 26
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
	le32(sb[76:80], 0)                 // s_rev_level = GOOD_OLD_REV -> 128-byte inodes
	le16(sb[56:58], 0xEF53)            // s_magic

	// block group descriptor table (block 2)
	gdt := block(2)
	le32(gdt[0:4], 0)                  // bg_block_bitmap (unused by our reader)
	le32(gdt[4:8], 0)                  // bg_inode_bitmap (unused by our reader)
	le32(gdt[8:12], testInodeTblBlock) // bg_inode_table

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
		for _, e := range entries {
			recLen := 8 + len(e.name)
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
	if _, err := fs.ReadFile("does-not-exist.txt"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestOpenRejectsBadMagic(t *testing.T) {
	junk := make([]byte, 4096)
	if _, err := Open(junk); err == nil {
		t.Fatal("expected an error for a non-ext2 image")
	}
}
