package diskimage

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPartitionWindowRejectsInvalidRanges(t *testing.T) {
	maxInt64 := int64(^uint64(0) >> 1)
	tests := []struct {
		name string
		part Partition
		size int64
		ok   bool
	}{
		{name: "valid exact end", part: Partition{StartByte: 100, LengthBytes: 900}, size: 1000, ok: true},
		{name: "negative start", part: Partition{StartByte: -1, LengthBytes: 1}, size: 1000},
		{name: "negative length", part: Partition{StartByte: 1, LengthBytes: -1}, size: 1000},
		{name: "zero length", part: Partition{StartByte: 1}, size: 1000},
		{name: "past disk", part: Partition{StartByte: 900, LengthBytes: 101}, size: 1000},
		{name: "signed wrap", part: Partition{StartByte: maxInt64 - 10, LengthBytes: 11}, size: maxInt64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, ok := partitionWindow(tc.part, tc.size)
			if ok != tc.ok {
				t.Fatalf("partitionWindow ok = %v, want %v", ok, tc.ok)
			}
		})
	}
}

func TestCheckedAddInt64RejectsOverflow(t *testing.T) {
	if _, ok := checkedAddInt64(int64(^uint64(0)>>1), 1); ok {
		t.Fatal("checkedAddInt64 accepted overflow")
	}
}

func TestFallbackWindowRejectsInvalidClaims(t *testing.T) {
	if _, ok := fallbackWindow(900, 1000, []Partition{{StartByte: 800, LengthBytes: 300}}); ok {
		t.Fatal("fallbackWindow accepted an offset inside a partition extending past the disk")
	}
	maxInt64 := int64(^uint64(0) >> 1)
	if _, ok := fallbackWindow(maxInt64-5, maxInt64, []Partition{{StartByte: maxInt64 - 10, LengthBytes: 20}}); ok {
		t.Fatal("fallbackWindow accepted an offset inside a wrapping partition")
	}
}

func TestProbeExtRejectsOffsetWrap(t *testing.T) {
	r := &countingZeroReaderAt{}
	if ProbeExt(r, int64(^uint64(0)>>1)) {
		t.Fatal("ProbeExt accepted a wrapping offset")
	}
	if r.calls != 0 {
		t.Fatalf("ProbeExt performed %d reads for a wrapping offset", r.calls)
	}
}

func TestFindFilesystemsHonoursMBRPartitionLength(t *testing.T) {
	fsImage := fakeExt2(t)
	disk := make([]byte, sectorSize+len(fsImage))
	copy(disk[sectorSize:], fsImage)
	disk[510] = mbrSignature0
	disk[511] = mbrSignature1
	entry := disk[446 : 446+16]
	entry[4] = 0x83
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	binary.LittleEndian.PutUint32(entry[12:16], 4)

	if filesystems := FindFilesystems(bytes.NewReader(disk), int64(len(disk))); len(filesystems) != 0 {
		t.Fatalf("FindFilesystems accepted %d filesystem(s) by reading past the declared partition", len(filesystems))
	}
}

func TestFindFilesystemsIgnoresOutOfImageMBREntriesForFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start uint32
	}{
		{name: "entry claims fallback offset", start: 1},
		{name: "entry would clip fallback window", start: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsImage := fakeExt2(t)
			disk := make([]byte, sectorSize+len(fsImage))
			copy(disk[sectorSize:], fsImage)
			disk[510] = mbrSignature0
			disk[511] = mbrSignature1
			entry := disk[446 : 446+16]
			entry[4] = 0x83
			binary.LittleEndian.PutUint32(entry[8:12], tc.start)
			binary.LittleEndian.PutUint32(entry[12:16], ^uint32(0))

			filesystems := FindFilesystems(bytes.NewReader(disk), int64(len(disk)))
			if len(filesystems) != 1 {
				t.Fatalf("FindFilesystems returned %d filesystems, want 1", len(filesystems))
			}
			got, err := filesystems[0].ReadFile("small.txt")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, smallContent) {
				t.Fatalf("small.txt = %q", got)
			}
		})
	}
}

func TestFindFilesystemsUsesOnlyValidMBREntriesAsFallbackBoundaries(t *testing.T) {
	fsImage := fakeExt2(t)
	validStart := sectorSize + len(fsImage)
	disk := make([]byte, validStart+sectorSize)
	copy(disk[sectorSize:], fsImage)
	disk[510] = mbrSignature0
	disk[511] = mbrSignature1

	invalid := disk[446 : 446+16]
	invalid[4] = 0x83
	binary.LittleEndian.PutUint32(invalid[8:12], 4)
	binary.LittleEndian.PutUint32(invalid[12:16], ^uint32(0))

	valid := disk[462 : 462+16]
	valid[4] = 0x83
	binary.LittleEndian.PutUint32(valid[8:12], uint32(validStart/sectorSize))
	binary.LittleEndian.PutUint32(valid[12:16], 1)

	filesystems := FindFilesystems(bytes.NewReader(disk), int64(len(disk)))
	if len(filesystems) != 1 {
		t.Fatalf("FindFilesystems returned %d filesystems, want 1", len(filesystems))
	}
	if got := filesystems[0].src.size(); got != int64(len(fsImage)) {
		t.Fatalf("fallback window size = %d, want valid-partition boundary at %d", got, len(fsImage))
	}
}

func TestFindFilesystemsPreservesValidFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{name: "raw filesystem", offset: 0},
		{name: "known fixed offset", offset: 0x100000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsImage := fakeExt2(t)
			disk := make([]byte, tc.offset+len(fsImage))
			copy(disk[tc.offset:], fsImage)
			filesystems := FindFilesystems(bytes.NewReader(disk), int64(len(disk)))
			if len(filesystems) != 1 {
				t.Fatalf("FindFilesystems returned %d filesystems, want 1", len(filesystems))
			}
			got, err := filesystems[0].ReadFile("small.txt")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, smallContent) {
				t.Fatalf("small.txt = %q", got)
			}
		})
	}
}

func TestFindFilesystemsBoundsFallbackWindowsToMBRIntervals(t *testing.T) {
	const nestedOffset = 0x100000
	tests := []struct {
		name           string
		filesystemBase int
		partitionStart uint32
		partitionEnd   int
	}{
		{
			name:           "raw candidate stops at next partition",
			filesystemBase: 0,
			partitionStart: 4,
			partitionEnd:   4*sectorSize + 4*sectorSize,
		},
		{
			name:           "nested candidate stops at partition end",
			filesystemBase: nestedOffset,
			partitionStart: 1,
			partitionEnd:   nestedOffset + 2*testBlockSize,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsImage := fakeExt2(t)
			disk := make([]byte, tc.filesystemBase+len(fsImage))
			copy(disk[tc.filesystemBase:], fsImage)
			disk[510] = mbrSignature0
			disk[511] = mbrSignature1
			entry := disk[446 : 446+16]
			entry[4] = 0x83
			binary.LittleEndian.PutUint32(entry[8:12], tc.partitionStart)
			startByte := int(tc.partitionStart) * sectorSize
			binary.LittleEndian.PutUint32(entry[12:16], uint32((tc.partitionEnd-startByte)/sectorSize))

			if filesystems := FindFilesystems(bytes.NewReader(disk), int64(len(disk))); len(filesystems) != 0 {
				t.Fatalf("FindFilesystems accepted %d filesystem(s) across an MBR boundary", len(filesystems))
			}
		})
	}
}

func TestFindFilesystemsScansPastOneGiB(t *testing.T) {
	const filesystemOffset = int64(1<<30) + filesystemScanStride
	image := fakeExt2(t)
	r := &sparseOverlayReaderAt{offset: filesystemOffset, data: image}
	filesystems := FindFilesystems(r, filesystemOffset+int64(len(image)))
	if len(filesystems) != 1 {
		t.Fatalf("FindFilesystems returned %d filesystems, want 1", len(filesystems))
	}
	got, err := filesystems[0].ReadFile("small.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, smallContent) {
		t.Fatalf("small.txt = %q", got)
	}
}

type sparseOverlayReaderAt struct {
	offset int64
	data   []byte
}

func (r *sparseOverlayReaderAt) ReadAt(p []byte, off int64) (int, error) {
	clear(p)
	start := max(off, r.offset)
	end := min(off+int64(len(p)), r.offset+int64(len(r.data)))
	if start < end {
		copy(p[start-off:end-off], r.data[start-r.offset:end-r.offset])
	}
	return len(p), nil
}

type countingZeroReaderAt struct {
	calls int
}

func (r *countingZeroReaderAt) ReadAt(p []byte, _ int64) (int, error) {
	r.calls++
	clear(p)
	return len(p), nil
}
