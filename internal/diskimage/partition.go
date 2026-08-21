package diskimage

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Partition is one entry of a DOS/MBR partition table.
type Partition struct {
	Bootable    bool
	Type        byte
	StartByte   int64
	LengthBytes int64
}

const (
	mbrSignature0 = 0x55
	mbrSignature1 = 0xAA
	maxPartitions = 4
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
		start := int64(binary.LittleEndian.Uint32(e[8:12])) * 512
		length := int64(binary.LittleEndian.Uint32(e[12:16])) * 512
		if e[4] == 0 || length == 0 {
			continue
		}
		parts = append(parts, Partition{
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
	sb := make([]byte, 2)
	if _, err := r.ReadAt(sb, off+superblockOffset+56); err != nil {
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
// Each candidate is fully validated by parsing its superblock and group
// descriptors; failures are skipped silently.
func FindFilesystems(r io.ReaderAt, size int64) []*FS {
	var candidates []int64

	if parts, err := ReadMBR(r); err == nil {
		for _, p := range parts {
			candidates = append(candidates, p.StartByte)
		}
	}
	candidates = append(candidates, 0, 512, 0x400000, 0x100000, 0x200000)
	for off := int64(0x400000); off < size; off += 0x400000 {
		candidates = append(candidates, off)
	}

	seen := map[int64]bool{}
	var out []*FS
	for _, off := range candidates {
		if off < 0 || off >= size || seen[off] || !ProbeExt(r, off) {
			continue
		}
		seen[off] = true
		fs, err := OpenAt(io.NewSectionReader(r, off, size-off), size-off)
		if err != nil {
			continue
		}
		out = append(out, fs)
	}
	return out
}
