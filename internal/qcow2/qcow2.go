// Package qcow2 is a minimal, read-only, pure-Go qcow2 (QEMU copy-on-write
// v2/v3) reader. FortiGate/FortiManager VM firmware (.out for KVM/VMware)
// decrypts to a qcow2 disk image rather than the appliances' bare
// MBR+ext3 layout, so the unpack pipeline needs to see through one before
// the ext filesystem work can start.
//
// Supported: standard v2/v3 images, uncompressed clusters, zlib-deflate
// compressed clusters, v3 all-zero cluster flag, sparse holes. Not
// supported: encryption, backing files, internal/external snapshots,
// extended L2 entries (v3 subclusters), external data files -- none of
// which Fortinet shipping images use.
package qcow2

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
)

var magic = [4]byte{'Q', 'F', 'I', 0xfb}

const (
	l1EntryMask   = 0x00fffffffffffe00 // bits 9-55: L2 table offset
	l2StdMask     = 0x00fffffffffffe00 // bits 9-55: cluster offset
	l2Compressed  = 1 << 62            // bit 62: compressed cluster
	l2ZeroFlag    = 1                  // bit 0 (v3): all-zero cluster
	maxClusterBit = 21                 // 2 MB clusters; sanity bound
)

// Reader is a read-only handle on a qcow2 image presenting its virtual
// (guest-visible) contents via io.ReaderAt.
type Reader struct {
	r           io.ReaderAt
	virtualSize int64

	clusterBits uint32
	clusterSize uint64

	l2Bits uint32
	l2Size uint64 // clusters per L2 table, in entries

	l1Table []uint64
}

// IsQCow2 reports whether data starts with the qcow2 magic bytes.
func IsQCow2(data []byte) bool {
	return len(data) >= 4 && bytes.Equal(data[:4], magic[:])
}

func readFullAt(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n == len(p) && (err == nil || err == io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}

// Open parses the qcow2 header and L1 table from r.
func Open(r io.ReaderAt) (*Reader, error) {
	hdr := make([]byte, 104)
	if err := readFullAt(r, hdr, 0); err != nil {
		return nil, fmt.Errorf("qcow2: reading header: %w", err)
	}
	if !bytes.Equal(hdr[0:4], magic[:]) {
		return nil, fmt.Errorf("qcow2: bad magic %x", hdr[0:4])
	}
	version := binary.BigEndian.Uint32(hdr[4:8])
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("qcow2: unsupported version %d (want 2 or 3)", version)
	}
	if version == 3 {
		incompatible := binary.BigEndian.Uint64(hdr[72:80])
		// Bit 0: dirty (refcounts may be inconsistent -- fine for reads of
		// a cleanly shut-down image, but flag it), bit 2: compression type
		// other than zlib, bit 3: extended L2 entries.
		if incompatible&(1<<2) != 0 {
			return nil, fmt.Errorf("qcow2: non-zlib compression type not supported")
		}
		if incompatible&(1<<3) != 0 {
			return nil, fmt.Errorf("qcow2: extended L2 entries not supported")
		}
	}

	clusterBits := binary.BigEndian.Uint32(hdr[20:24])
	if clusterBits < 9 || clusterBits > maxClusterBit {
		return nil, fmt.Errorf("qcow2: implausible cluster_bits %d", clusterBits)
	}
	rd := &Reader{
		r:           r,
		virtualSize: int64(binary.BigEndian.Uint64(hdr[24:32])),
		clusterBits: clusterBits,
		clusterSize: 1 << clusterBits,
		l2Bits:      clusterBits - 3,
		l2Size:      1 << (clusterBits - 3),
	}
	if crypt := binary.BigEndian.Uint32(hdr[32:36]); crypt != 0 {
		return nil, fmt.Errorf("qcow2: encrypted images not supported")
	}
	l1Size := binary.BigEndian.Uint32(hdr[36:40])
	l1Off := binary.BigEndian.Uint64(hdr[40:48])
	if l1Size == 0 || l1Size > 1<<28 {
		return nil, fmt.Errorf("qcow2: implausible l1_size %d", l1Size)
	}
	if rd.virtualSize == 0 {
		return nil, fmt.Errorf("qcow2: zero virtual size")
	}

	buf := make([]byte, int(l1Size)*8)
	if err := readFullAt(r, buf, int64(l1Off)); err != nil {
		return nil, fmt.Errorf("qcow2: reading L1 table (%d entries): %w", l1Size, err)
	}
	rd.l1Table = make([]uint64, l1Size)
	for i := range rd.l1Table {
		rd.l1Table[i] = binary.BigEndian.Uint64(buf[i*8 : i*8+8])
	}
	return rd, nil
}

// Size returns the guest-visible virtual disk size in bytes.
func (r *Reader) Size() int64 { return r.virtualSize }

// l2Table loads the L2 table for the given L1 index, or nil if the L1
// entry is unallocated (guest reads there are holes).
func (r *Reader) l2Table(l1Index int) ([]uint64, error) {
	if l1Index < 0 || l1Index >= len(r.l1Table) {
		return nil, nil
	}
	off := r.l1Table[l1Index] & l1EntryMask
	if off == 0 {
		return nil, nil
	}
	buf := make([]byte, r.clusterSize)
	if err := readFullAt(r.r, buf, int64(off)); err != nil {
		return nil, fmt.Errorf("qcow2: reading L2 table at %d: %w", off, err)
	}
	table := make([]uint64, r.l2Size)
	for i := range table {
		table[i] = binary.BigEndian.Uint64(buf[i*8 : i*8+8])
	}
	return table, nil
}

// clusterData materializes the guest cluster containing the given virtual
// byte offset.
func (r *Reader) clusterData(voff int64) ([]byte, error) {
	cluster := uint64(voff) >> r.clusterBits
	l2EntriesPerL1 := r.l2Size
	l1Index := int(cluster / l2EntriesPerL1)
	l2Index := int(cluster % l2EntriesPerL1)

	out := make([]byte, r.clusterSize) // zero-filled: holes read as zeros

	l2, err := r.l2Table(l1Index)
	if err != nil {
		return nil, err
	}
	if l2 == nil {
		return out, nil
	}
	entry := l2[l2Index]

	if entry&l2Compressed != 0 {
		csizeShift := 62 - (r.clusterBits - 8)
		csizeMask := uint64(1)<<(r.clusterBits-8) - 1
		coffset := entry & ((uint64(1) << csizeShift) - 1)
		nbSectors := ((entry >> csizeShift) & csizeMask) + 1
		csize := nbSectors*512 - (coffset & 511)
		raw := make([]byte, csize)
		if n, err := r.r.ReadAt(raw, int64(coffset)); err != nil && n < len(raw) {
			// tolerate a short tail: the sector-rounded csize can run
			// past end of file for a stream that ends mid-sector
			raw = raw[:n]
		}
		// qemu writes compressed clusters as a raw deflate stream
		// (deflateInit2 with negative window bits), not zlib-framed.
		zr := flate.NewReader(bytes.NewReader(raw))
		defer zr.Close()
		if _, err := io.ReadFull(zr, out); err != nil {
			return nil, fmt.Errorf("qcow2: inflating compressed cluster at %d: %w", coffset, err)
		}
		return out, nil
	}

	if entry&l2ZeroFlag != 0 {
		return out, nil
	}
	coffset := entry & l2StdMask
	if coffset == 0 {
		return out, nil
	}
	if err := readFullAt(r.r, out, int64(coffset)); err != nil {
		return nil, fmt.Errorf("qcow2: reading cluster at %d: %w", coffset, err)
	}
	return out, nil
}

// ReadAt implements io.ReaderAt over the guest-visible contents.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= r.virtualSize {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		if off >= r.virtualSize {
			return n, io.EOF
		}
		inCluster := uint64(off) & (r.clusterSize - 1)
		take := uint64(len(p) - n)
		if rem := r.clusterSize - inCluster; take > rem {
			take = rem
		}
		if virtEnd := uint64(r.virtualSize) - uint64(off); take > virtEnd {
			take = virtEnd
		}
		cd, err := r.clusterData(off)
		if err != nil {
			return n, err
		}
		copy(p[n:n+int(take)], cd[inCluster:inCluster+take])
		n += int(take)
		off += int64(take)
	}
	return n, nil
}
