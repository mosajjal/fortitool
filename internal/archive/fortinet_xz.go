package archive

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

var xzMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

const (
	xzStreamHeaderSize       = 12
	xzStreamFooterSize       = 12
	xzSHA256CheckSize        = 32
	xzSHA256CheckID          = 0x0a
	fortinetStreamHeaderCRC  = uint32(0xffff0000)
	fortinetOtherCRC         = uint32(0xffffffff)
	minSingleRecordIndexSize = 8
)

type xzChecksumPatch struct {
	offset int
	value  [4]byte
}

// fortinetXZReader recognises the checksum placeholders used by one observed
// Fortinet XZ variant. Only a single-stream, single-block stream with a
// SHA-256 block check and all four expected placeholders is repaired. Standard
// XZ input is returned byte-for-byte through the ordinary decoder path.
func fortinetXZReader(data []byte) (io.Reader, error) {
	patches, ok, err := fortinetXZChecksumPatches(data)
	if err != nil {
		return nil, err
	}
	if !ok {
		return newByteReader(data), nil
	}
	return &xzChecksumPatchReader{
		reader:  newByteReader(data),
		patches: patches,
	}, nil
}

func fortinetXZChecksumPatches(data []byte) (patches [4]xzChecksumPatch, ok bool, err error) {
	if len(data) < xzStreamHeaderSize || !bytes.Equal(data[:len(xzMagic)], xzMagic) {
		return patches, false, nil
	}
	if binary.LittleEndian.Uint32(data[8:xzStreamHeaderSize]) != fortinetStreamHeaderCRC {
		return patches, false, nil
	}

	variation := func(format string, args ...any) ([4]xzChecksumPatch, bool, error) {
		return patches, true, fmt.Errorf("xz: unsupported Fortinet checksum-placeholder variation: "+format, args...)
	}
	if len(data) < xzStreamHeaderSize+xzStreamFooterSize+minSingleRecordIndexSize {
		return variation("stream is truncated")
	}
	if data[6] != 0 || data[7] != xzSHA256CheckID {
		return variation("stream flags are %02x%02x, want 000a", data[6], data[7])
	}

	footerOffset := len(data) - xzStreamFooterSize
	footer := data[footerOffset:]
	if footer[10] != 'Y' || footer[11] != 'Z' {
		return variation("stream footer is missing")
	}
	if footer[8] != 0 || footer[9] != xzSHA256CheckID {
		return variation("header and footer flags differ")
	}
	if binary.LittleEndian.Uint32(footer[:4]) != fortinetOtherCRC {
		return variation("footer checksum placeholder does not match")
	}

	indexSize := (uint64(binary.LittleEndian.Uint32(footer[4:8])) + 1) * 4
	maxIndexSize := uint64(len(data) - xzStreamHeaderSize - xzStreamFooterSize)
	if indexSize < minSingleRecordIndexSize || indexSize > maxIndexSize {
		return variation("invalid index size")
	}
	indexEnd := footerOffset
	indexStart := indexEnd - int(indexSize)
	index := data[indexStart:indexEnd]
	if index[0] != 0 {
		return variation("index indicator does not match")
	}
	if binary.LittleEndian.Uint32(index[len(index)-4:]) != fortinetOtherCRC {
		return variation("index checksum placeholder does not match")
	}

	indexBody := index[:len(index)-4]
	pos := 1
	records, readErr := readXZVLI(indexBody, &pos)
	if readErr != nil {
		return variation("invalid index record count: %v", readErr)
	}
	if records != 1 {
		return variation("index contains %d records, want 1", records)
	}
	unpaddedSize, readErr := readXZVLI(indexBody, &pos)
	if readErr != nil {
		return variation("invalid block size: %v", readErr)
	}
	if _, readErr = readXZVLI(indexBody, &pos); readErr != nil {
		return variation("invalid uncompressed size: %v", readErr)
	}
	paddingSize := len(indexBody) - pos
	wantPaddingSize := (4 - pos%4) % 4
	if paddingSize != wantPaddingSize {
		return variation("index padding has length %d, want %d", paddingSize, wantPaddingSize)
	}
	for ; pos < len(indexBody); pos++ {
		if indexBody[pos] != 0 {
			return variation("index padding is not zero")
		}
	}

	blockStart := xzStreamHeaderSize
	if indexStart <= blockStart || data[blockStart] == 0 {
		return variation("block header is missing")
	}
	blockHeaderSize := (int(data[blockStart]) + 1) * 4
	blockHeaderEnd := blockStart + blockHeaderSize
	if blockHeaderSize < 8 || blockHeaderEnd > indexStart {
		return variation("invalid block header size")
	}
	blockCRCOffset := blockHeaderEnd - 4
	if binary.LittleEndian.Uint32(data[blockCRCOffset:blockHeaderEnd]) != fortinetOtherCRC {
		return variation("block-header checksum placeholder does not match")
	}
	if unpaddedSize < uint64(blockHeaderSize+xzSHA256CheckSize) {
		return variation("block is too short for its header and SHA-256 check")
	}
	paddedSize := (unpaddedSize + 3) &^ uint64(3)
	if paddedSize != uint64(indexStart-blockStart) {
		return variation("index does not describe exactly one block")
	}
	blockPaddingStart := blockStart + int(unpaddedSize) - xzSHA256CheckSize
	checkStart := blockStart + int(paddedSize) - xzSHA256CheckSize
	for _, b := range data[blockPaddingStart:checkStart] {
		if b != 0 {
			return variation("block padding is not zero")
		}
	}

	patches[0] = newXZChecksumPatch(8, data[6:8])
	patches[1] = newXZChecksumPatch(blockCRCOffset, data[blockStart:blockCRCOffset])
	patches[2] = newXZChecksumPatch(indexEnd-4, data[indexStart:indexEnd-4])
	patches[3] = newXZChecksumPatch(footerOffset, footer[4:10])
	return patches, true, nil
}

func newXZChecksumPatch(offset int, protected []byte) xzChecksumPatch {
	patch := xzChecksumPatch{offset: offset}
	binary.LittleEndian.PutUint32(patch.value[:], crc32.ChecksumIEEE(protected))
	return patch
}

type xzChecksumPatchReader struct {
	reader  io.Reader
	pos     int
	patches [4]xzChecksumPatch
}

func (r *xzChecksumPatchReader) Read(p []byte) (n int, err error) {
	start := r.pos
	n, err = r.reader.Read(p)
	r.pos += n
	end := start + n
	for _, patch := range r.patches {
		patchStart := patch.offset
		if patchStart < start {
			patchStart = start
		}
		patchEnd := patch.offset + len(patch.value)
		if patchEnd > end {
			patchEnd = end
		}
		if patchStart < patchEnd {
			copy(p[patchStart-start:patchEnd-start], patch.value[patchStart-patch.offset:patchEnd-patch.offset])
		}
	}
	return n, err
}

func readXZVLI(data []byte, pos *int) (uint64, error) {
	var value uint64
	for i := 0; i < 9; i++ {
		if *pos >= len(data) {
			return 0, fmt.Errorf("unterminated VLI")
		}
		b := data[*pos]
		(*pos)++
		if i > 0 && b == 0 {
			return 0, fmt.Errorf("non-canonical VLI")
		}
		value |= uint64(b&0x7f) << uint(i*7)
		if b&0x80 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("VLI exceeds 63 bits")
}
