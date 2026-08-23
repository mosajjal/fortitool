// Package kernelpayload extracts the decompressed kernel image embedded in
// a Fortinet flatkc container, replacing the `gunzip` subprocess call every
// reference tool (forticrack_v8, fgx) shells out for.
package kernelpayload

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

const (
	minKernelPayloadSize = 1_000_000
	maxKernelPayloadSize = 512 << 20
)

// Extract finds the (possibly not-first) gzip member inside a flatkc blob
// and decompresses it, returning the member whose decompressed size looks
// kernel-sized (>1MB) -- flatkc containers can carry more than one gzip
// member (bootstrap stub, compressed kernel, ...).
func Extract(flatkc []byte) (payload []byte, gzipOffset int, err error) {
	return extract(flatkc, maxKernelPayloadSize)
}

func extract(flatkc []byte, maxExpanded int64) (payload []byte, gzipOffset int, err error) {
	if maxExpanded <= minKernelPayloadSize {
		return nil, 0, fmt.Errorf("kernel gzip expansion limit %d must exceed minimum payload size %d", maxExpanded, minKernelPayloadSize)
	}
	const magicScanStep = 1
	var candidateErr error
	off := bytes.Index(flatkc, []byte{0x1f, 0x8b, 0x08})
	for off != -1 {
		if r, err := gzip.NewReader(bytes.NewReader(flatkc[off:])); err == nil {
			// A flatkc may contain adjacent gzip members or non-gzip installer
			// data after the selected kernel member. Only the selected member is
			// decoded, but its body and trailer must complete successfully.
			r.Multistream(false)
			out, readErr := io.ReadAll(io.LimitReader(r, maxExpanded+1))
			_ = r.Close()
			switch {
			case readErr != nil:
				candidateErr = fmt.Errorf("gzip member at offset %d: %w", off, readErr)
			case int64(len(out)) > maxExpanded:
				candidateErr = fmt.Errorf("gzip member at offset %d expands past %d bytes", off, maxExpanded)
			case len(out) > minKernelPayloadSize:
				return out, off, nil
			}
		}
		next := bytes.Index(flatkc[off+magicScanStep:], []byte{0x1f, 0x8b, 0x08})
		if next == -1 {
			break
		}
		off = off + magicScanStep + next
	}
	if candidateErr != nil {
		return nil, 0, fmt.Errorf("no complete kernel-sized gzip member found in flatkc: %w", candidateErr)
	}
	return nil, 0, errors.New("no complete kernel-sized gzip member found in flatkc")
}
