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

func TestExtractRejectsCorruptKernelGzipTrailer(t *testing.T) {
	kernel := bytes.Repeat([]byte("kernelbytes-"), 100_000)
	member := gzipBytes(t, kernel)
	member[len(member)-8] ^= 0xff
	if _, _, err := Extract(append([]byte("flatkc-prefix"), member...)); err == nil {
		t.Fatal("expected a corrupt kernel gzip trailer to fail")
	}
}

func TestExtractRejectsTruncatedKernelGzip(t *testing.T) {
	kernel := bytes.Repeat([]byte("kernelbytes-"), 100_000)
	member := gzipBytes(t, kernel)
	if _, _, err := Extract(append([]byte("flatkc-prefix"), member[:len(member)-4]...)); err == nil {
		t.Fatal("expected a truncated kernel gzip member to fail")
	}
}

func TestExtractDoesNotMergeConcatenatedMembers(t *testing.T) {
	small := gzipBytes(t, bytes.Repeat([]byte("small"), 100))
	kernel := bytes.Repeat([]byte("kernelbytes-"), 100_000)
	large := gzipBytes(t, kernel)
	prefix := []byte("flatkc-prefix")
	flatkc := append(append(append([]byte{}, prefix...), small...), large...)

	payload, off, err := Extract(flatkc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, kernel) {
		t.Fatalf("payload includes the wrong gzip member: got %d bytes", len(payload))
	}
	if want := len(prefix) + len(small); off != want {
		t.Fatalf("gzip offset = %d, want %d", off, want)
	}
}

func TestExtractAllowsFortinetTailAfterCompleteMember(t *testing.T) {
	kernel := bytes.Repeat([]byte("kernelbytes-"), 100_000)
	member := gzipBytes(t, kernel)
	flatkc := append(append([]byte("flatkc-prefix"), member...), []byte("non-gzip Fortinet tail")...)

	payload, _, err := Extract(flatkc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, kernel) {
		t.Fatalf("payload = %d bytes, want %d", len(payload), len(kernel))
	}
}

func TestExtractRejectsKernelExpansionPastLimit(t *testing.T) {
	limit := int64(minKernelPayloadSize + 64)
	kernel := bytes.Repeat([]byte("k"), int(limit)+1)
	member := gzipBytes(t, kernel)
	if _, _, err := extract(member, limit); err == nil {
		t.Fatal("expected kernel gzip expansion past the limit to fail")
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
