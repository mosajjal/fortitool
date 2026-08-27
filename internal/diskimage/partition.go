package diskimage

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Partition is one entry of a DOS/MBR partition table.
type Partition struct {
	Index       int
	Bootable    bool
	Type        byte
	StartByte   int64
	LengthBytes int64
}

// FilesystemLocation describes how FindFilesystems reached a volume without
// changing the discovery order or validation used to select it.
type FilesystemLocation struct {
	Kind           string
	Offset         int64
	Length         int64
	PartitionIndex int
}

// LocatedFilesystem couples a readable filesystem with its discovery result.
type LocatedFilesystem struct {
	FS       *FS
	Location FilesystemLocation
}

const (
	mbrSignature0        = 0x55
	mbrSignature1        = 0xAA
	maxPartitions        = 4
	sectorSize           = 512
	filesystemScanStride = 0x400000
)

// ReadMBR parses the DOS partition table of a disk whose first sector
// starts at byte 0 of r. Returns nil (no error) if the 0x55AA signature
// is absent -- many FortiOS images carry their filesystem without any
// partition table at all.
func ReadMBR(r io.ReaderAt) ([]Partition, error) {
	sector := make([]byte, 512)
	if _, err := r.ReadAt(sector, 0); err != nil {
		return nil, fmt.Errorf("diskimage: reading MBR sector: %w", err)
	}
	if sector[510] != mbrSignature0 || sector[511] != mbrSignature1 {
		return nil, nil
	}
	var parts []Partition
	for i := 0; i < maxPartitions; i++ {
		e := sector[446+i*16 : 446+(i+1)*16]
		start := sectorsToBytes(binary.LittleEndian.Uint32(e[8:12]))
		length := sectorsToBytes(binary.LittleEndian.Uint32(e[12:16]))
		if e[4] == 0 || length == 0 {
			continue
		}
		parts = append(parts, Partition{
			Index:       i + 1,
			Bootable:    e[0]&0x80 != 0,
			Type:        e[4],
			StartByte:   start,
			LengthBytes: length,
		})
	}
	return parts, nil
}

// ProbeExt checks whether a valid ext superblock sits at the given byte
// offset of r (i.e. the filesystem would start there).
func ProbeExt(r io.ReaderAt, off int64) bool {
	superMagic, ok := checkedAddInt64(off, superblockOffset+56)
	if !ok {
		return false
	}
	sb := make([]byte, 2)
	if _, err := r.ReadAt(sb, superMagic); err != nil {
		return false
	}
	return binary.LittleEndian.Uint16(sb) == ext2Magic
}

// FindFilesystems locates every readable ext2/3/4 filesystem in a disk
// image. Strategy, in order:
//  1. DOS/MBR partition table entries (appliance images: ext3 @ sector 1;
//     VM images: a boot partition among several).
//  2. Known fixed offsets seen across the product line (e.g. some
//     FortiManager images keep the volume at 0x400000 with no MBR).
//  3. A coarse aligned scan as a last resort.
//
// Each candidate is validated by parsing its superblock and root inode
// metadata; failures are skipped silently.
func FindFilesystems(r io.ReaderAt, size int64) []*FS {
	located := FindFilesystemVolumes(r, size)
	out := make([]*FS, 0, len(located))
	for _, volume := range located {
		out = append(out, volume.FS)
	}
	return out
}

// FindFilesystemVolumes is FindFilesystems with the selected candidate's
// existing discovery metadata exposed for reporting callers.
func FindFilesystemVolumes(r io.ReaderAt, size int64) []LocatedFilesystem {
	if size < 0 {
		return nil
	}
	type candidate struct {
		offset         int64
		length         int64
		kind           string
		partitionIndex int
	}
	var candidates []candidate
	claimedPartitionOffsets := make(map[int64]struct{})
	var partitions []Partition

	if parts, err := ReadMBR(io.NewSectionReader(r, 0, size)); err == nil {
		for _, p := range parts {
			if off, length, ok := partitionWindow(p, size); ok {
				partitions = append(partitions, p)
				claimedPartitionOffsets[off] = struct{}{}
				candidates = append(candidates, candidate{
					offset: off, length: length, kind: "mbr-partition", partitionIndex: p.Index,
				})
			}
		}
	}
	for _, off := range []int64{0, 512, 0x400000, 0x100000, 0x200000} {
		if _, claimed := claimedPartitionOffsets[off]; !claimed {
			if length, ok := fallbackWindow(off, size, partitions); ok {
				kind := "fixed-offset"
				if off == 0 {
					kind = "raw"
				}
				candidates = append(candidates, candidate{offset: off, length: length, kind: kind})
			}
		}
	}
	for off := int64(filesystemScanStride); off < size; {
		if _, claimed := claimedPartitionOffsets[off]; !claimed {
			if length, ok := fallbackWindow(off, size, partitions); ok {
				candidates = append(candidates, candidate{offset: off, length: length, kind: "scanned-offset"})
			}
		}
		if size-off <= filesystemScanStride {
			break
		}
		off += filesystemScanStride
	}

	seen := map[int64]bool{}
	var out []LocatedFilesystem
	for _, candidate := range candidates {
		if seen[candidate.offset] {
			continue
		}
		seen[candidate.offset] = true
		if !probeExtWindow(r, candidate.offset, candidate.length) {
			continue
		}
		fs, err := OpenAt(io.NewSectionReader(r, candidate.offset, candidate.length), candidate.length)
		if err != nil {
			continue
		}
		out = append(out, LocatedFilesystem{
			FS: fs,
			Location: FilesystemLocation{
				Kind: candidate.kind, Offset: candidate.offset, Length: candidate.length,
				PartitionIndex: candidate.partitionIndex,
			},
		})
	}
	return out
}

func sectorsToBytes(sectors uint32) int64 {
	return int64(sectors) * sectorSize
}

func checkedAddInt64(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a > int64(^uint64(0)>>1)-b {
		return 0, false
	}
	return a + b, true
}

func partitionWindow(part Partition, diskSize int64) (int64, int64, bool) {
	end, ok := checkedAddInt64(part.StartByte, part.LengthBytes)
	if !ok || part.LengthBytes == 0 || end > diskSize {
		return 0, 0, false
	}
	return part.StartByte, part.LengthBytes, true
}

// fallbackWindow keeps a non-partition candidate inside the MBR interval or
// unpartitioned gap that contains it. Invalid claimed ranges are not scanned.
func fallbackWindow(off, diskSize int64, partitions []Partition) (int64, bool) {
	if off < 0 || off >= diskSize {
		return 0, false
	}
	end := diskSize
	for _, part := range partitions {
		partEnd, ok := checkedAddInt64(part.StartByte, part.LengthBytes)
		if !ok || part.LengthBytes == 0 {
			if off >= part.StartByte {
				return 0, false
			}
			if part.StartByte > off && part.StartByte < end {
				end = part.StartByte
			}
			continue
		}
		if part.StartByte > off && part.StartByte < end {
			end = part.StartByte
		}
		if off >= part.StartByte && off < partEnd {
			if partEnd > diskSize {
				return 0, false
			}
			if partEnd < end {
				end = partEnd
			}
		}
	}
	if end <= off {
		return 0, false
	}
	return end - off, true
}

func probeExtWindow(r io.ReaderAt, off, length int64) bool {
	required := int64(superblockOffset + 56 + 2)
	if off < 0 || length < required {
		return false
	}
	return ProbeExt(r, off)
}
