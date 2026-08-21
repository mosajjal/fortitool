package qcow2

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

const testClusterBits = 16 // 64 KiB clusters

func buildHeader(t *testing.T, virtualSize uint64, l1Size uint32, l1Off uint64) []byte {
	t.Helper()
	hdr := make([]byte, 104)
	copy(hdr[0:4], magic[:])
	binary.BigEndian.PutUint32(hdr[4:8], 3)
	binary.BigEndian.PutUint32(hdr[20:24], testClusterBits)
	binary.BigEndian.PutUint64(hdr[24:32], virtualSize)
	binary.BigEndian.PutUint32(hdr[36:40], l1Size)
	binary.BigEndian.PutUint64(hdr[40:48], l1Off)
	return hdr
}

// buildImage assembles a qcow2 v3 image from a list of (guestOffset,
// data) clusters. Uncovered regions read back as zeros.
func buildImage(t *testing.T, virtualSize uint64, clusters map[uint64][]byte) []byte {
	t.Helper()
	clusterSize := uint64(1) << testClusterBits
	l2Size := clusterSize / 8
	numL1 := int((virtualSize + l2Size*clusterSize - 1) / (l2Size * clusterSize))

	l1Off := uint64(104)
	// host allocations (L2 tables + data) must be cluster-aligned, as real
	// qcow2 allocators guarantee -- the L1/L2 entry masks strip low bits
	clustersStart := (l1Off + uint64(numL1)*8 + clusterSize - 1) / clusterSize * clusterSize

	img := bytes.NewBuffer(buildHeader(t, virtualSize, uint32(numL1), l1Off))
	for uint64(img.Len()) < clustersStart {
		img.WriteByte(0)
	}

	l1 := make([]uint64, numL1)
	l2Tables := make(map[int][]byte)     // l1Index -> raw L2 table bytes
	hostAlloc := make(map[uint64][]byte) // host offset -> cluster bytes
	nextHost := clustersStart

	writeCluster := func(data []byte) uint64 {
		off := nextHost
		nextHost += clusterSize
		buf := make([]byte, clusterSize)
		copy(buf, data)
		hostAlloc[off] = buf
		return off
	}

	for goff, data := range clusters {
		if uint64(len(data)) > clusterSize {
			t.Fatalf("cluster %d larger than cluster size", goff)
		}
		cluster := goff / clusterSize
		l1Index := int(cluster / l2Size)
		l2Index := int(cluster % l2Size)

		if _, ok := l2Tables[l1Index]; !ok {
			l2Tables[l1Index] = make([]byte, clusterSize)
			l1[l1Index] = writeCluster(l2Tables[l1Index])
		}
		entry := writeCluster(data) | 1<<63
		binary.BigEndian.PutUint64(l2Tables[l1Index][l2Index*8:l2Index*8+8], entry)
	}

	// emit host clusters in allocation order; L2 tables were snapshotted
	// empty at allocation time, so patch their final contents in first
	for l1Index, raw := range l2Tables {
		copy(hostAlloc[l1[l1Index]], raw)
	}
	written := clustersStart
	for written < nextHost {
		chunk, ok := hostAlloc[written]
		if !ok {
			t.Fatalf("hole in host allocation at %d", written)
		}
		img.Write(chunk)
		written += clusterSize
	}
	full := img.Bytes()
	l1Raw := make([]byte, numL1*8)
	for i := range l1 {
		binary.BigEndian.PutUint64(l1Raw[i*8:i*8+8], l1[i]|1<<63)
	}
	copy(full[l1Off:], l1Raw)
	return full
}

func TestOpenRejectsBadMagic(t *testing.T) {
	if _, err := Open(bytes.NewReader(make([]byte, 200))); err == nil {
		t.Fatal("expected error for non-qcow2 data")
	}
}

func TestReadUncompressedAndHoles(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	c1 := make([]byte, clusterSize)
	for i := range c1 {
		c1[i] = byte(i)
	}
	c3 := make([]byte, clusterSize)
	rand.Read(c3)
	// cluster 0 at guest offset 0, cluster 3 leaves a hole at cluster 1-2
	img := buildImage(t, clusterSize*8, map[uint64][]byte{
		0:               c1,
		3 * clusterSize: c3,
	})

	rd, err := Open(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if rd.Size() != int64(clusterSize*8) {
		t.Fatalf("Size() = %d, want %d", rd.Size(), clusterSize*8)
	}

	got := make([]byte, clusterSize)
	if _, err := rd.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt cluster0: %v", err)
	}
	if !bytes.Equal(got, c1) {
		t.Fatal("cluster 0 mismatch")
	}

	got = make([]byte, clusterSize)
	if _, err := rd.ReadAt(got, int64(3*clusterSize)); err != nil {
		t.Fatalf("ReadAt cluster3: %v", err)
	}
	if !bytes.Equal(got, c3) {
		t.Fatal("cluster 3 mismatch")
	}

	// hole reads as zeros
	got = make([]byte, clusterSize)
	n, err := rd.ReadAt(got, int64(clusterSize))
	if n != int(clusterSize) || (err != nil && err != io.EOF) {
		t.Fatalf("ReadAt hole: n=%d err=%v", n, err)
	}
	for _, b := range got {
		if b != 0 {
			t.Fatal("hole should read as zeros")
		}
	}

	// read spanning cluster boundary
	span := make([]byte, 128)
	want := append(append([]byte{}, c1[clusterSize-64:]...), c3[:0]...)
	_ = want
	if _, err := rd.ReadAt(span, int64(clusterSize)-64); err != nil {
		t.Fatalf("spanning ReadAt: %v", err)
	}
	for i := 0; i < 64; i++ {
		if span[i] != c1[clusterSize-64+uint64(i)] {
			t.Fatal("spanning read first half mismatch")
		}
	}
}

func TestReadCompressedCluster(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	orig := make([]byte, clusterSize)
	for i := range orig {
		orig[i] = byte(i * 7)
	}
	var comp bytes.Buffer
	fw, _ := flate.NewWriter(&comp, flate.DefaultCompression)
	fw.Write(orig)
	fw.Close()

	// hand-build an image with a compressed L2 entry:
	// header @0, L1 table (1 entry) @104, L2 table @clusterSize,
	// compressed data after the L2 table
	virtualSize := clusterSize * 2
	l1Off := uint64(104)
	l2Off := clusterSize
	dataOff := uint64(l2Off + clusterSize)
	hdr := buildHeader(t, virtualSize, 1, l1Off)

	l2 := make([]byte, clusterSize)
	// compressed entry: bit62 set; csize_shift = 62-(16-8) = 54;
	// bits 54..61 hold nb_csectors-1; low bits hold the host offset
	nbSectors := (uint64(comp.Len()) + 511) / 512
	entry := uint64(1)<<62 | ((nbSectors - 1) << 54) | dataOff
	binary.BigEndian.PutUint64(l2[0:8], entry)

	img := bytes.NewBuffer(hdr)
	for img.Len() < int(l2Off) {
		img.WriteByte(0)
	}
	img.Write(l2)
	img.Write(comp.Bytes())

	l1Raw := make([]byte, 8)
	binary.BigEndian.PutUint64(l1Raw, l2Off|1<<63)
	full := img.Bytes()
	copy(full[l1Off:], l1Raw)

	rd, err := Open(bytes.NewReader(full))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := make([]byte, clusterSize)
	if _, err := rd.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt compressed: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatal("compressed cluster round-trip mismatch")
	}
}
