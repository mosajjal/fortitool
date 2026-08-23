package qcow2

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"strings"
	"testing"
)

const testClusterBits = 16 // 64 KiB clusters

type fullReadEOFReader struct {
	r io.ReaderAt
}

func (r fullReadEOFReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.r.ReadAt(p, off)
	if n == len(p) {
		return n, io.EOF
	}
	return n, err
}

func buildHeaderVersion(t testing.TB, version uint32, virtualSize uint64, l1Size uint32, l1Off uint64) []byte {
	t.Helper()
	hdr := make([]byte, 104)
	copy(hdr[0:4], magic[:])
	binary.BigEndian.PutUint32(hdr[4:8], version)
	binary.BigEndian.PutUint32(hdr[20:24], testClusterBits)
	binary.BigEndian.PutUint64(hdr[24:32], virtualSize)
	binary.BigEndian.PutUint32(hdr[36:40], l1Size)
	binary.BigEndian.PutUint64(hdr[40:48], l1Off)
	if version == 3 {
		binary.BigEndian.PutUint32(hdr[96:100], 4)
		binary.BigEndian.PutUint32(hdr[100:104], 104)
	}
	return hdr
}

func buildHeader(t testing.TB, virtualSize uint64, l1Size uint32, l1Off uint64) []byte {
	t.Helper()
	return buildHeaderVersion(t, 3, virtualSize, l1Size, l1Off)
}

func setRefcountHeader(hdr []byte, tableOff uint64) {
	binary.BigEndian.PutUint64(hdr[48:56], tableOff)
	binary.BigEndian.PutUint32(hdr[56:60], 1)
}

func populateRefcounts(t testing.TB, img []byte, clusterSize, tableOff, blockOff, allocatedEnd uint64) {
	t.Helper()
	if tableOff+clusterSize > uint64(len(img)) || blockOff+clusterSize > uint64(len(img)) {
		t.Fatal("refcount metadata extends past image")
	}
	binary.BigEndian.PutUint64(img[tableOff:tableOff+8], blockOff)
	clusters := (allocatedEnd + clusterSize - 1) / clusterSize
	if clusters > clusterSize/2 {
		t.Fatal("fixture needs more than one refcount block")
	}
	for cluster := uint64(0); cluster < clusters; cluster++ {
		off := blockOff + cluster*2
		binary.BigEndian.PutUint16(img[off:off+2], 1)
	}
}

// buildImageVersion assembles a qcow2 image from a list of (guestOffset,
// data) clusters. Uncovered regions read back as zeros.
func buildImageVersion(t testing.TB, version uint32, virtualSize uint64, clusters map[uint64][]byte) []byte {
	t.Helper()
	clusterSize := uint64(1) << testClusterBits
	l2Size := clusterSize / 8
	numL1 := int((virtualSize + l2Size*clusterSize - 1) / (l2Size * clusterSize))

	l1Off := clusterSize
	// host allocations (L2 tables + data) must be cluster-aligned, as real
	// qcow2 allocators guarantee -- the L1/L2 entry masks strip low bits
	refcountTableOff := (l1Off + uint64(numL1)*8 + clusterSize - 1) / clusterSize * clusterSize
	refcountBlockOff := refcountTableOff + clusterSize
	clustersStart := refcountBlockOff + clusterSize

	hdr := buildHeaderVersion(t, version, virtualSize, uint32(numL1), l1Off)
	setRefcountHeader(hdr, refcountTableOff)
	img := bytes.NewBuffer(hdr)
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
		entry := l1[i]
		if entry != 0 {
			entry |= 1 << 63
		}
		binary.BigEndian.PutUint64(l1Raw[i*8:i*8+8], entry)
	}
	copy(full[l1Off:], l1Raw)
	populateRefcounts(t, full, clusterSize, refcountTableOff, refcountBlockOff, nextHost)
	return full
}

func buildImage(t testing.TB, virtualSize uint64, clusters map[uint64][]byte) []byte {
	t.Helper()
	return buildImageVersion(t, 3, virtualSize, clusters)
}

func requireOpenError(t *testing.T, img []byte, contains string) {
	t.Helper()
	_, err := Open(bytes.NewReader(img))
	if err == nil {
		t.Fatalf("Open succeeded, want error containing %q", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("Open error = %q, want substring %q", err, contains)
	}
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

func TestFullReadWithEOFAccepted(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	want := bytes.Repeat([]byte{0x5a}, int(clusterSize))
	img := buildImage(t, clusterSize, map[uint64][]byte{0: want})

	rd, err := Open(fullReadEOFReader{r: bytes.NewReader(img)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := make([]byte, clusterSize)
	if n, err := rd.ReadAt(got, 0); n != len(got) || err != nil {
		t.Fatalf("ReadAt: n=%d err=%v", n, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("cluster mismatch")
	}
}

func TestReadUnallocatedL1Region(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	guestBytesPerL1 := clusterSize * (clusterSize / 8)
	img := buildImage(t, guestBytesPerL1+clusterSize, map[uint64][]byte{0: {0x5a}})

	rd, err := Open(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := bytes.Repeat([]byte{0xff}, 16)
	if _, err := rd.ReadAt(got, int64(guestBytesPerL1)); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatalf("unallocated L1 region read = %x", got)
	}
}

func TestReadVersion2UncompressedCluster(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	want := bytes.Repeat([]byte{0x5a}, int(clusterSize))
	img := buildImageVersion(t, 2, clusterSize, map[uint64][]byte{0: want})

	rd, err := Open(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := make([]byte, clusterSize)
	if _, err := rd.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("version 2 cluster mismatch")
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
	// header @0, L1 table @clusterSize, L2 table @2*clusterSize,
	// compressed data after the L2 table
	virtualSize := clusterSize * 2
	l1Off := clusterSize
	l2Off := 2 * clusterSize
	refcountTableOff := 3 * clusterSize
	refcountBlockOff := 4 * clusterSize
	dataOff := uint64(5*clusterSize + 1)
	hdr := buildHeader(t, virtualSize, 1, l1Off)
	setRefcountHeader(hdr, refcountTableOff)

	l2 := make([]byte, clusterSize)
	// compressed entry: bit62 set; csize_shift = 62-(16-8) = 54;
	// bits 54..61 hold nb_csectors-1; low bits hold the host offset
	nbSectors := (uint64(comp.Len()) + (dataOff & 511) + 511) / 512
	entry := uint64(1)<<62 | ((nbSectors - 1) << 54) | dataOff
	binary.BigEndian.PutUint64(l2[0:8], entry)

	img := bytes.NewBuffer(hdr)
	for img.Len() < int(l2Off) {
		img.WriteByte(0)
	}
	img.Write(l2)
	for img.Len() < int(dataOff) {
		img.WriteByte(0)
	}
	img.Write(comp.Bytes())
	declaredEnd := dataOff + nbSectors*512 - (dataOff & 511)
	for uint64(img.Len()) < declaredEnd {
		img.WriteByte(0)
	}

	l1Raw := make([]byte, 8)
	binary.BigEndian.PutUint64(l1Raw, l2Off|1<<63)
	full := img.Bytes()
	copy(full[l1Off:], l1Raw)
	populateRefcounts(t, full, clusterSize, refcountTableOff, refcountBlockOff, uint64(len(full)))

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

	short := append([]byte(nil), full[:dataOff+uint64(comp.Len())]...)
	shortReader, err := Open(bytes.NewReader(short))
	if err != nil {
		t.Fatalf("Open short compressed image: %v", err)
	}
	if _, err := shortReader.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt short compressed image: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatal("short compressed cluster round-trip mismatch")
	}

	bad := append([]byte(nil), full...)
	binary.BigEndian.PutUint64(bad[l2Off:l2Off+8], entry|1<<63)
	badReader, err := Open(bytes.NewReader(bad))
	if err != nil {
		t.Fatalf("Open copied compressed entry: %v", err)
	}
	if _, err := badReader.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("ReadAt succeeded with copied flag on compressed entry")
	}
}

func TestOpenRejectsBackingFile(t *testing.T) {
	img := buildImage(t, 1<<testClusterBits, nil)
	binary.BigEndian.PutUint64(img[8:16], 112)
	binary.BigEndian.PutUint32(img[16:20], 4)
	copy(img[112:116], "base")
	requireOpenError(t, img, "backing")
}

func TestOpenValidatesIncompatibleFeatures(t *testing.T) {
	base := buildImage(t, 1<<testClusterBits, nil)
	tests := []struct {
		name    string
		bit     uint
		wantErr string
	}{
		{name: "dirty", bit: 0, wantErr: "dirty"},
		{name: "corrupt", bit: 1, wantErr: "corrupt"},
		{name: "external_data", bit: 2, wantErr: "external data"},
		{name: "compression_type", bit: 3, wantErr: "compression"},
		{name: "extended_l2", bit: 4, wantErr: "extended L2"},
		{name: "reserved_5", bit: 5, wantErr: "unknown incompatible"},
		{name: "reserved_63", bit: 63, wantErr: "unknown incompatible"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := append([]byte(nil), base...)
			binary.BigEndian.PutUint64(img[72:80], uint64(1)<<tt.bit)
			if tt.bit == 3 {
				binary.BigEndian.PutUint32(img[100:104], 112)
				img[104] = 1
			}
			if tt.wantErr != "" {
				requireOpenError(t, img, tt.wantErr)
				return
			}
			if _, err := Open(bytes.NewReader(img)); err != nil {
				t.Fatalf("Open: %v", err)
			}
		})
	}
}

func TestOpenAllowsUnknownCompatibleAndAutoclearFeatures(t *testing.T) {
	img := buildImage(t, 1<<testClusterBits, nil)
	binary.BigEndian.PutUint64(img[80:88], 1<<63)
	binary.BigEndian.PutUint64(img[88:96], 1<<63)
	if _, err := Open(bytes.NewReader(img)); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

func TestOpenRejectsRawDataAutoclearWithoutDataFile(t *testing.T) {
	img := buildImage(t, 1<<testClusterBits, nil)
	binary.BigEndian.PutUint64(img[88:96], autoclearDataFileRaw)
	requireOpenError(t, img, "requires an external data file")
}

func TestVersion2IgnoresVersion3FeatureFields(t *testing.T) {
	img := buildImageVersion(t, 2, 1<<testClusterBits, nil)
	binary.BigEndian.PutUint64(img[72:80], 1<<63)
	if _, err := Open(bytes.NewReader(img)); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

func TestOpenRejectsUnrepresentableVirtualSize(t *testing.T) {
	for _, size := range []uint64{uint64(math.MaxInt64) + 1, math.MaxUint64} {
		img := buildImage(t, 1<<testClusterBits, nil)
		binary.BigEndian.PutUint64(img[24:32], size)
		requireOpenError(t, img, "virtual size")
	}
}

func TestOpenRejectsInsufficientL1Coverage(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	l2Entries := clusterSize / 8
	img := buildImage(t, clusterSize, nil)
	binary.BigEndian.PutUint64(img[24:32], clusterSize*l2Entries+1)
	requireOpenError(t, img, "L1 table is too small")
}

type maxReadReader struct {
	header  []byte
	maxRead int
}

func (r *maxReadReader) ReadAt(p []byte, off int64) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	if off == 0 && len(p) == len(r.header) {
		copy(p, r.header)
		return len(p), nil
	}
	return 0, io.EOF
}

func TestOpenChecksL1SpanBeforeAllocation(t *testing.T) {
	const l1Entries = 1 << 20
	r := &maxReadReader{
		header: buildHeader(t, 1<<testClusterBits, l1Entries, 1<<testClusterBits),
	}
	if _, err := Open(r); err == nil {
		t.Fatal("Open succeeded with an absent L1 table")
	}
	if r.maxRead != len(r.header) {
		t.Fatalf("largest read = %d, want %d-byte header", r.maxRead, len(r.header))
	}
}

func TestOpenRejectsOversizedL1TableBeforeAllocation(t *testing.T) {
	const maxL1Bytes = 32 << 20
	r := &maxReadReader{
		header: buildHeader(t, 1<<testClusterBits, maxL1Bytes/8+1, 1<<testClusterBits),
	}
	_, err := Open(r)
	if err == nil {
		t.Fatal("Open succeeded with an oversized L1 table")
	}
	if !strings.Contains(err.Error(), "L1 table too large") {
		t.Fatalf("Open error = %q, want oversized L1 table error", err)
	}
	if r.maxRead != len(r.header) {
		t.Fatalf("largest read = %d, want %d-byte header", r.maxRead, len(r.header))
	}
}

func TestOpenRejectsInvalidL1TableLayout(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	t.Run("unaligned", func(t *testing.T) {
		hdr := buildHeader(t, clusterSize, 1, clusterSize+512)
		requireOpenError(t, hdr, "L1 table offset")
	})
	t.Run("past_end", func(t *testing.T) {
		hdr := buildHeader(t, clusterSize, 1, clusterSize)
		img := make([]byte, clusterSize+7)
		copy(img, hdr)
		requireOpenError(t, img, "L1 table")
	})
	t.Run("offset_above_maxint64", func(t *testing.T) {
		hdr := buildHeader(t, clusterSize, 1, uint64(math.MaxInt64)+1)
		requireOpenError(t, hdr, "MaxInt64")
	})
	t.Run("span_above_maxint64", func(t *testing.T) {
		const l1Entries = 1 << 13
		off := uint64(math.MaxInt64) & ^(clusterSize - 1)
		hdr := buildHeader(t, clusterSize, l1Entries, off)
		requireOpenError(t, hdr, "MaxInt64")
	})
}

func TestOpenRejectsInvalidL1Entries(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	base := buildImage(t, clusterSize, map[uint64][]byte{0: {0x5a}})
	l1Off := clusterSize
	original := binary.BigEndian.Uint64(base[l1Off : l1Off+8])
	tests := []struct {
		name string
		bit  uint
	}{
		{name: "reserved_0", bit: 0},
		{name: "reserved_56", bit: 56},
		{name: "reserved_62", bit: 62},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := append([]byte(nil), base...)
			binary.BigEndian.PutUint64(img[l1Off:l1Off+8], original|uint64(1)<<tt.bit)
			requireOpenError(t, img, "reserved bits")
		})
	}
	t.Run("unaligned_l2_table", func(t *testing.T) {
		img := append([]byte(nil), base...)
		l2Off := original & 0x00fffffffffffe00
		binary.BigEndian.PutUint64(img[l1Off:l1Off+8], l2Off+512|1<<63)
		requireOpenError(t, img, "L2 table offset")
	})
	t.Run("l2_table_past_end", func(t *testing.T) {
		img := append([]byte(nil), base...)
		pastEnd := uint64(len(img)+int(clusterSize)-1) & ^(clusterSize - 1)
		binary.BigEndian.PutUint64(img[l1Off:l1Off+8], pastEnd|1<<63)
		requireOpenError(t, img, "L2 table")
	})
}

func TestReadRejectsInvalidStandardL2Entries(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	base := buildImage(t, clusterSize, map[uint64][]byte{0: {0x5a}})
	l1Off := clusterSize
	l2Off := binary.BigEndian.Uint64(base[l1Off:l1Off+8]) & 0x00fffffffffffe00
	original := binary.BigEndian.Uint64(base[l2Off : l2Off+8])
	tests := []struct {
		name  string
		entry uint64
	}{
		{name: "reserved_low", entry: original | 1<<1},
		{name: "reserved_high", entry: original | 1<<56},
		{name: "unaligned_data", entry: original + 512},
		{name: "copied_without_offset", entry: 1 << 63},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := append([]byte(nil), base...)
			binary.BigEndian.PutUint64(img[l2Off:l2Off+8], tt.entry)
			rd, err := Open(bytes.NewReader(img))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if _, err := rd.ReadAt(make([]byte, 1), 0); err == nil {
				t.Fatal("ReadAt succeeded with an invalid L2 entry")
			}
		})
	}
}

func TestReadRejectsCompressedReservedOffsetBits(t *testing.T) {
	const clusterSize = uint64(512)
	const l1Off = clusterSize
	const l2Off = 2 * clusterSize
	const refcountTableOff = 3 * clusterSize
	const refcountBlockOff = 4 * clusterSize

	hdr := buildHeader(t, clusterSize, 1, l1Off)
	binary.BigEndian.PutUint32(hdr[20:24], 9)
	setRefcountHeader(hdr, refcountTableOff)
	img := make([]byte, 5*clusterSize)
	copy(img, hdr)
	binary.BigEndian.PutUint64(img[l1Off:l1Off+8], l2Off|l2Copied)
	binary.BigEndian.PutUint64(img[l2Off:l2Off+8], l2Compressed|1<<56)
	populateRefcounts(t, img, clusterSize, refcountTableOff, refcountBlockOff, uint64(len(img)))

	rd, err := Open(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := rd.ReadAt(make([]byte, 1), 0); err == nil || !strings.Contains(err.Error(), "reserved offset bits") {
		t.Fatalf("ReadAt error = %v, want reserved compressed offset bits error", err)
	}
}

func TestReadRejectsVersion2ZeroFlag(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	img := buildImageVersion(t, 2, clusterSize, map[uint64][]byte{0: {0x5a}})
	l1Off := clusterSize
	l2Off := binary.BigEndian.Uint64(img[l1Off:l1Off+8]) & 0x00fffffffffffe00
	entry := binary.BigEndian.Uint64(img[l2Off : l2Off+8])
	binary.BigEndian.PutUint64(img[l2Off:l2Off+8], entry|1)

	rd, err := Open(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := rd.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("ReadAt succeeded with a version 2 zero flag")
	}
}

func TestReadVersion3ZeroFlag(t *testing.T) {
	clusterSize := uint64(1) << testClusterBits
	img := buildImage(t, clusterSize, map[uint64][]byte{0: {0x5a}})
	l1Off := clusterSize
	l2Off := binary.BigEndian.Uint64(img[l1Off:l1Off+8]) & 0x00fffffffffffe00
	entry := binary.BigEndian.Uint64(img[l2Off : l2Off+8])
	binary.BigEndian.PutUint64(img[l2Off:l2Off+8], entry|1)

	rd, err := Open(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := bytes.Repeat([]byte{0xff}, 16)
	if _, err := rd.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatalf("zero cluster read = %x", got)
	}
}

func FuzzOpenAndRead(f *testing.F) {
	clusterSize := uint64(1) << testClusterBits
	f.Add(buildImage(f, clusterSize, nil))
	f.Add(buildImageVersion(f, 2, clusterSize, map[uint64][]byte{0: {0x5a}}))
	f.Add([]byte("not qcow2"))
	f.Fuzz(func(t *testing.T, img []byte) {
		rd, err := Open(bytes.NewReader(img))
		if err != nil || rd.Size() == 0 {
			return
		}
		buf := make([]byte, 1)
		_, _ = rd.ReadAt(buf, 0)
	})
}
