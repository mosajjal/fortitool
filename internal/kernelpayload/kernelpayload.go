// Package kernelpayload extracts the decompressed kernel image embedded in
// a Fortinet flatkc container, replacing the `gunzip` subprocess call every
// reference tool (forticrack_v8, fgx) shells out for.
package kernelpayload

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
)

// Extract finds the (possibly not-first) gzip member inside a flatkc blob
// and decompresses it, returning the member whose decompressed size looks
// kernel-sized (>1MB) -- flatkc containers can carry more than one gzip
// member (bootstrap stub, compressed kernel, ...).
func Extract(flatkc []byte) (payload []byte, gzipOffset int, err error) {
	const magicScanStep = 1
	off := bytes.Index(flatkc, []byte{0x1f, 0x8b, 0x08})
	for off != -1 {
		if r, err := gzip.NewReader(bytes.NewReader(flatkc[off:])); err == nil {
			out, readErr := io.ReadAll(r)
			// A truncated/garbage-trailing stream still yields a partial
			// decompressed buffer; accept it if it's kernel-sized, same
			// tolerance the Python reference implementation uses.
			if len(out) > 1_000_000 && (readErr == nil || errors.Is(readErr, io.ErrUnexpectedEOF) || readErr == io.EOF) {
				return out, off, nil
			}
			if len(out) > 1_000_000 {
				return out, off, nil
			}
		}
		next := bytes.Index(flatkc[off+magicScanStep:], []byte{0x1f, 0x8b, 0x08})
		if next == -1 {
			break
		}
		off = off + magicScanStep + next
	}
	return nil, 0, errors.New("no kernel-sized gzip member found in flatkc")
}
