package diskimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// fakeExt4Extents builds a minimal ext-style image whose data file is
// extent-mapped (as in ext4), exercising the extent-tree reader: a root
// node with depth 1, one index entry, and a leaf with two extents
// separated by a hole.
//
// Block layout (1024-byte blocks):
//
//	0       unused (boot block)
//	1       superblock
//	2       block group descriptor table
//	3       inode table (4 inodes * 128 bytes, one block)
//	4       root dir data
//	5       inode bitmap
//	6       extent tree leaf node (depth 0)
//	7-8     sparse.data first extent (2 blocks)
//	9-10    hole (logical blocks 2-3)
//	11      sparse.data second extent (1 block)
const (
	extBlockSize = 1024
)

var sparseContent = func() []byte {
	// logical blocks 0,1 = "AAAA..."; block 2,3 = hole; block 4 = "CCCC..."
	b := make([]byte, 5*extBlockSize)
	for i := 0; i < 2*extBlockSize; i++ {
		b[i] = 'A'
	}
	for i := 4 * extBlockSize; i < 5*extBlockSize; i++ {
		b[i] = 'C'
	}
	return b
}()

func buildExtentFS(t testing.TB) []byte {
	t.Helper()
	totalBlocks := 12
	img := make([]byte, totalBlocks*extBlockSize)
	block := func(n int) []byte { return img[n*extBlockSize : (n+1)*extBlockSize] }
	le32 := binary.LittleEndian.PutUint32
	le16 := binary.LittleEndian.PutUint16

	sb := block(1)
	le32(sb[0:4], 8)                     // s_inodes_count
	le32(sb[4:8], uint32(totalBlocks))   // s_blocks_count
	le32(sb[20:24], 1)                   // s_first_data_block
	le32(sb[24:28], 0)                   // 1024-byte blocks
	le32(sb[32:36], uint32(totalBlocks)) // s_blocks_per_group
	le32(sb[40:44], 8)                   // s_inodes_per_group
	le32(sb[76:80], 1)                   // s_rev_level = dynamic
	le16(sb[56:58], 0xEF53)
	le16(sb[88:90], 128) // s_inode_size
	le32(sb[96:100], extFeatureIncompatFiletype|extFeatureIncompatExtents)

	gdt := block(2)
	le32(gdt[4:8], 5)  // bg_inode_bitmap
	le32(gdt[8:12], 3) // bg_inode_table
	block(5)[0] = 0x07

	writeInode := func(num uint32, mode uint16, size uint32, fill func(raw []byte)) {
		off := (3 * extBlockSize) + int(num-1)*128
		raw := img[off : off+128]
		le16(raw[0:2], mode)
		le32(raw[4:8], size)
		if fill != nil {
			fill(raw[40:100])
		}
	}

	const (
		sIFDIR = 0o040000
		sIFREG = 0o100000
	)

	// root directory inode: direct block 4
	writeInode(2, sIFDIR|0o755, extBlockSize, func(raw []byte) {
		le32(raw[0:4], 4)
	})

	// sparse.data inode: extent tree rooted at i_block
	writeInode(3, sIFREG|0o644, uint32(len(sparseContent)), func(raw []byte) {
		// root header @ i_block[0..]: magic, entries=1, max=4, depth=1
		le16(raw[0:2], 0xF30A)
		le16(raw[2:4], 1)
		le16(raw[4:6], 4)
		le16(raw[6:8], 1) // depth 1 -> index entries follow
		// index entry: ei_block=0, leaf at block 6
		le32(raw[12:16], 0)
		le32(raw[16:20], 6)
	})
	binary.LittleEndian.PutUint32(img[3*extBlockSize+2*128+32:3*extBlockSize+2*128+36], inodeFlagExtents)

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
	writeDirBlock(4, []dirEnt{
		{2, 2, "."},
		{2, 2, ".."},
		{3, 1, "sparse.data"},
	})

	// extent leaf node (block 6): two extents with a hole between them
	leaf := block(6)
	le16(leaf[0:2], 0xF30A)
	le16(leaf[2:4], 2) // entries
	le16(leaf[4:6], 4)
	le16(leaf[6:8], 0) // depth 0 -> extent entries
	// extent 0: logical 0, len 2, physical 7
	le32(leaf[12:16], 0)
	le16(leaf[16:18], 2)
	le16(leaf[18:20], 0)
	le32(leaf[20:24], 7)
	// extent 1: logical 4, len 1, physical 11 (logical 2-3 are a hole)
	le32(leaf[24:28], 4)
	le16(leaf[28:30], 1)
	le16(leaf[30:32], 0)
	le32(leaf[32:36], 11)

	copy(block(7), sparseContent[0:extBlockSize])
	copy(block(8), sparseContent[extBlockSize:2*extBlockSize])
	copy(block(11), sparseContent[4*extBlockSize:5*extBlockSize])

	return img
}

func TestReadExtentMappedFile(t *testing.T) {
	fs, err := Open(buildExtentFS(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := fs.ReadFile("sparse.data")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, sparseContent) {
		t.Fatalf("extent content mismatch: got %d bytes", len(got))
	}
	for i := 0; i < 2*extBlockSize; i++ {
		if got[i] != 'A' {
			t.Fatalf("first extent corrupt at %d", i)
		}
	}
	for i := 2 * extBlockSize; i < 4*extBlockSize; i++ {
		if got[i] != 0 {
			t.Fatalf("hole should read as zeros, got %x at %d", got[i], i)
		}
	}
	for i := 4 * extBlockSize; i < 5*extBlockSize; i++ {
		if got[i] != 'C' {
			t.Fatalf("second extent corrupt at %d", i)
		}
	}
}

func TestReadExtentMappedFilePropagatesBlockReadFailures(t *testing.T) {
	for _, block := range []int{6, 7} {
		t.Run(fmt.Sprintf("block-%d", block), func(t *testing.T) {
			img := buildExtentFS(t)
			start := int64(block * extBlockSize)
			fs, err := OpenAt(failingReaderAt{
				reader:    bytes.NewReader(img),
				failStart: start,
				failEnd:   start + extBlockSize,
			}, int64(len(img)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fs.ReadFile("sparse.data"); !errors.Is(err, errSyntheticBlockRead) {
				t.Fatalf("ReadFile error = %v, want synthetic block read failure", err)
			}
		})
	}
}

func TestFindFilesystemsOnRawImage(t *testing.T) {
	// filesystem image preceded by a 512-byte MBR sector carrying one
	// partition entry pointing at sector 1 -- the classic appliance layout
	fsImg := buildExtentFS(t)
	img := make([]byte, 512+len(fsImg))
	copy(img[512:], fsImg)
	img[510] = 0x55
	img[511] = 0xAA
	entry := img[446 : 446+16]
	binary.LittleEndian.PutUint32(entry[8:12], 1)                         // start sector
	binary.LittleEndian.PutUint32(entry[12:16], uint32(len(img)-512)/512) // sectors
	entry[4] = 0x83                                                       // Linux

	fss := FindFilesystems(bytes.NewReader(img), int64(len(img)))
	if len(fss) != 1 {
		t.Fatalf("FindFilesystems found %d filesystems, want 1", len(fss))
	}
	if _, err := fss[0].ReadFile("sparse.data"); err != nil {
		t.Fatalf("ReadFile via FindFilesystems: %v", err)
	}
}
