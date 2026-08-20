package kernelpayload

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestExtractFindsKernelSizedMember(t *testing.T) {
	// A flatkc container in the wild has a small bootstrap gzip member
	// followed by the real (large) compressed kernel; Extract must skip
	// the small one and pick the kernel-sized one.
	small := gzipBytes(t, bytes.Repeat([]byte("x"), 100))
	kernel := bytes.Repeat([]byte("kernelbytes-"), 100_000) // >1MB decompressed
	large := gzipBytes(t, kernel)

	flatkc := append([]byte("FORTINET-HEADER-JUNK"), small...)
	flatkc = append(flatkc, []byte("more junk between members")...)
	flatkc = append(flatkc, large...)

	payload, off, err := Extract(flatkc)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if !bytes.Equal(payload, kernel) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(payload), len(kernel))
	}
	if off < len(flatkc)-len(large) {
		t.Fatalf("offset %d looks wrong, expected the second gzip member", off)
	}
}

func TestExtractNoGzipMember(t *testing.T) {
	if _, _, err := Extract([]byte("not a flatkc at all")); err == nil {
		t.Fatal("expected an error when no gzip member is present")
	}
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
