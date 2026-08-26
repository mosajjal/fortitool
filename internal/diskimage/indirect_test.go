package diskimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const indirectTestBlockSize = 16

func buildIndirectFixture(t *testing.T, totalBlocks int, sparse map[int]bool) (*FS, *inode, []byte) {
	t.Helper()
	const blockCount = 512
	data := make([]byte, blockCount*indirectTestBlockSize)
	expected := make([]byte, 0, totalBlocks*indirectTestBlockSize)
	for logical := 0; logical < totalBlocks; logical++ {
		block := make([]byte, indirectTestBlockSize)
		if !sparse[logical] {
			for i := range block {
				block[i] = byte(logical + 1)
			}
			copy(data[(logical+1)*indirectTestBlockSize:], block)
		}
		expected = append(expected, block...)
	}

	in := &inode{mode: s_IFREG | 0o644, sizeLo: uint32(len(expected))}
	for logical := 0; logical < nDirect && logical < totalBlocks; logical++ {
		if !sparse[logical] {
			in.block[logical] = uint32(logical + 1)
		}
	}

	ptrsPerBlock := indirectTestBlockSize / 4
	nextPointerBlock := uint32(128)
	var buildTree func(level, start, capacity int) uint32
	buildTree = func(level, start, capacity int) uint32 {
		if start >= totalBlocks {
			return 0
		}
		end := start + capacity
		if end > totalBlocks {
			end = totalBlocks
		}
		allSparse := true
		for logical := start; logical < end; logical++ {
			if !sparse[logical] {
				allSparse = false
				break
			}
		}
		if allSparse {
			return 0
		}
		block := nextPointerBlock
		nextPointerBlock++
		childCapacity := 1
		if level > 1 {
			childCapacity = capacity / ptrsPerBlock
		}
		for i := 0; i < ptrsPerBlock; i++ {
			logical := start + i*childCapacity
			var pointer uint32
			if level == 1 {
				if logical < totalBlocks && !sparse[logical] {
					pointer = uint32(logical + 1)
				}
			} else {
				pointer = buildTree(level-1, logical, childCapacity)
			}
			binary.LittleEndian.PutUint32(data[int(block)*indirectTestBlockSize+i*4:], pointer)
		}
		return block
	}

	singleCapacity := ptrsPerBlock
	doubleCapacity := ptrsPerBlock * ptrsPerBlock
	tripleCapacity := doubleCapacity * ptrsPerBlock
	in.block[iBlockSingle] = buildTree(1, nDirect, singleCapacity)
	in.block[iBlockDouble] = buildTree(2, nDirect+singleCapacity, doubleCapacity)
	in.block[iBlockTriple] = buildTree(3, nDirect+singleCapacity+doubleCapacity, tripleCapacity)

	fs := &FS{
		src:    sliceSource{data: data},
		sb:     superblock{blockSize: indirectTestBlockSize, blocksCount: blockCount},
		fsSize: uint64(len(data)),
	}
	return fs, in, expected
}

func TestReadInodeDataIndirectBoundaries(t *testing.T) {
	tests := map[string]int{
		"direct-to-single": 13,
		"single-to-double": 17,
		"double-to-triple": 33,
	}
	for name, totalBlocks := range tests {
		t.Run(name, func(t *testing.T) {
			fs, in, expected := buildIndirectFixture(t, totalBlocks, nil)
			got, err := fs.readInodeDataIndirect(9, in)
			if err != nil {
				t.Fatalf("readInodeDataIndirect: %v", err)
			}
			if !bytes.Equal(got, expected) {
				t.Fatalf("reconstruction differs at %s boundary", name)
			}
		})
	}
}

func TestReadInodeDataIndirectTripleDataDeterministic(t *testing.T) {
	fs, in, expected := buildIndirectFixture(t, 40, nil)
	first, err := fs.readInodeDataIndirect(10, in)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	second, err := fs.readInodeDataIndirect(10, in)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if !bytes.Equal(first, expected) || !bytes.Equal(first, second) {
		t.Fatal("triple-indirect reconstruction is not exact and deterministic")
	}
}

func TestReadInodeDataIndirectExactPartialTail(t *testing.T) {
	fs, in, expected := buildIndirectFixture(t, 33, nil)
	in.sizeLo -= 3
	expected = expected[:len(expected)-3]
	got, err := fs.readInodeDataIndirect(10, in)
	if err != nil {
		t.Fatalf("readInodeDataIndirect: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("partial reconstruction differs: got %d bytes, want %d", len(got), len(expected))
	}
}

func TestReadInodeDataIndirectSparseTripleBranch(t *testing.T) {
	sparse := make(map[int]bool)
	for logical := 32; logical < 48; logical++ {
		sparse[logical] = true
	}
	fs, in, expected := buildIndirectFixture(t, 49, sparse)
	got, err := fs.readInodeDataIndirect(11, in)
	if err != nil {
		t.Fatalf("readInodeDataIndirect: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatal("sparse triple-indirect subtree was not reconstructed as holes")
	}
	if !bytes.Equal(got[32*indirectTestBlockSize:48*indirectTestBlockSize], make([]byte, 16*indirectTestBlockSize)) {
		t.Fatal("sparse triple-indirect branch contains non-zero data")
	}
}

func TestReadInodeDataIndirectDoesNotWalkUnusedTriplePointers(t *testing.T) {
	fs, in, expected := buildIndirectFixture(t, 33, nil)
	data := fs.src.(sliceSource).data
	root := in.block[iBlockTriple]
	double := binary.LittleEndian.Uint32(data[int(root)*indirectTestBlockSize:])
	single := binary.LittleEndian.Uint32(data[int(double)*indirectTestBlockSize:])
	for _, pointerBlock := range []uint32{root, double, single} {
		for i := 1; i < indirectTestBlockSize/4; i++ {
			binary.LittleEndian.PutUint32(data[int(pointerBlock)*indirectTestBlockSize+i*4:], 0xffffffff)
		}
	}
	got, err := fs.readInodeDataIndirect(12, in)
	if err != nil {
		t.Fatalf("readInodeDataIndirect: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatal("unused triple-indirect pointers changed reconstruction")
	}
}

func TestReadInodeDataIndirectRejectsTruncatedPointerBlock(t *testing.T) {
	data := make([]byte, 19*indirectTestBlockSize+8)
	in := &inode{mode: s_IFREG | 0o644, sizeLo: 13 * indirectTestBlockSize}
	for i := 0; i < nDirect; i++ {
		in.block[i] = uint32(i + 1)
	}
	in.block[iBlockSingle] = 19
	fs := &FS{src: sliceSource{data: data}, sb: superblock{blockSize: indirectTestBlockSize, blocksCount: 64}, fsSize: uint64(len(data))}
	if _, err := fs.readInodeDataIndirect(13, in); err == nil || !strings.Contains(err.Error(), "runs past filesystem boundary") {
		t.Fatalf("expected truncated pointer-block error, got %v", err)
	}
}

func TestReadInodeDataIndirectRejectsOutOfRangePointers(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		data := make([]byte, 8*indirectTestBlockSize)
		in := &inode{mode: s_IFREG | 0o644, sizeLo: indirectTestBlockSize}
		in.block[0] = 8
		fs := &FS{src: sliceSource{data: data}, sb: superblock{blockSize: indirectTestBlockSize, blocksCount: 8}, fsSize: uint64(len(data))}
		if _, err := fs.readInodeDataIndirect(14, in); err == nil || !strings.Contains(err.Error(), "outside filesystem") {
			t.Fatalf("expected out-of-range direct pointer error, got %v", err)
		}
	})
	t.Run("pointer-table", func(t *testing.T) {
		data := make([]byte, 16*indirectTestBlockSize)
		in := &inode{mode: s_IFREG | 0o644, sizeLo: 13 * indirectTestBlockSize}
		in.block[iBlockSingle] = 16
		fs := &FS{src: sliceSource{data: data}, sb: superblock{blockSize: indirectTestBlockSize, blocksCount: 16}, fsSize: uint64(len(data))}
		if _, err := fs.readInodeDataIndirect(15, in); err == nil || !strings.Contains(err.Error(), "outside filesystem") {
			t.Fatalf("expected out-of-range pointer-table error, got %v", err)
		}
	})
	t.Run("indirect-data", func(t *testing.T) {
		data := make([]byte, 32*indirectTestBlockSize)
		in := &inode{mode: s_IFREG | 0o644, sizeLo: 13 * indirectTestBlockSize}
		in.block[iBlockSingle] = 20
		binary.LittleEndian.PutUint32(data[20*indirectTestBlockSize:], 32)
		fs := &FS{src: sliceSource{data: data}, sb: superblock{blockSize: indirectTestBlockSize, blocksCount: 32}, fsSize: uint64(len(data))}
		if _, err := fs.readInodeDataIndirect(16, in); err == nil || !strings.Contains(err.Error(), "outside filesystem") {
			t.Fatalf("expected out-of-range indirect pointer error, got %v", err)
		}
	})
}

func TestReadInodeDataIndirectPropagatesTripleReadFailures(t *testing.T) {
	base, in, _ := buildIndirectFixture(t, 33, nil)
	data := base.src.(sliceSource).data
	root := in.block[iBlockTriple]
	double := binary.LittleEndian.Uint32(data[int(root)*indirectTestBlockSize:])
	single := binary.LittleEndian.Uint32(data[int(double)*indirectTestBlockSize:])
	dataBlock := binary.LittleEndian.Uint32(data[int(single)*indirectTestBlockSize:])
	for _, block := range []uint32{root, double, single, dataBlock} {
		t.Run(fmt.Sprintf("block-%d", block), func(t *testing.T) {
			start := int64(block * indirectTestBlockSize)
			fs := &FS{
				src: readerSource{
					r: failingReaderAt{
						reader:    bytes.NewReader(data),
						failStart: start,
						failEnd:   start + indirectTestBlockSize,
					},
					sz: int64(len(data)),
				},
				sb:     base.sb,
				fsSize: uint64(len(data)),
			}
			if _, err := fs.readInodeDataIndirect(17, in); !errors.Is(err, errSyntheticBlockRead) {
				t.Fatalf("readInodeDataIndirect error = %v, want synthetic block read failure", err)
			}
		})
	}
}

func TestReadInodeDataIndirectSupportsSparseFileLargerThanSource(t *testing.T) {
	data := make([]byte, 8*indirectTestBlockSize)
	in := &inode{mode: s_IFREG | 0o644, sizeLo: uint32(len(data) + 1)}
	fs := &FS{src: sliceSource{data: data}, sb: superblock{blockSize: indirectTestBlockSize, blocksCount: 8}, fsSize: uint64(len(data))}
	got, err := fs.readInodeDataIndirect(18, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != int(in.sizeLo) || !bytes.Equal(got, make([]byte, in.sizeLo)) {
		t.Fatalf("sparse file reconstruction returned %d bytes, want %d zero bytes", len(got), in.sizeLo)
	}
}

func TestReadInodeDataIndirectRejectsCapacityOverflow(t *testing.T) {
	fs := &FS{
		src: sliceSource{},
		sb:  superblock{blockSize: ^uint32(0) - 3, blocksCount: 1},
	}
	want := "triple-indirect capacity overflows"
	if strconv.IntSize == 32 {
		want = "invalid block size"
	}
	if _, err := fs.readInodeDataIndirect(19, &inode{}); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected %q error, got %v", want, err)
	}
}

func TestReadInodeDataIndirectRejectsReusedPointerBlock(t *testing.T) {
	const blockCount = 128
	data := make([]byte, blockCount*indirectTestBlockSize)
	binary.LittleEndian.PutUint32(data[100*indirectTestBlockSize:100*indirectTestBlockSize+4], 101)
	binary.LittleEndian.PutUint32(data[100*indirectTestBlockSize+4:100*indirectTestBlockSize+8], 101)
	in := &inode{mode: s_IFREG | 0o644, sizeLo: 21 * indirectTestBlockSize}
	in.block[iBlockDouble] = 100
	fs := &FS{
		src:    sliceSource{data: data},
		sb:     superblock{blockSize: indirectTestBlockSize, blocksCount: blockCount},
		fsSize: uint64(len(data)),
	}
	if _, err := fs.readInodeDataIndirect(20, in); err == nil || !strings.Contains(err.Error(), "indirect tree reuses block 101") {
		t.Fatalf("expected reused-pointer rejection, got %v", err)
	}
}
