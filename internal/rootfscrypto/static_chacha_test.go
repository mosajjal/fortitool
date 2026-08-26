package rootfscrypto

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"strings"
	"testing"
)

func buildStaticChaChaRootfs(t *testing.T, state []byte) ([]byte, []byte) {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	payload := bytes.Repeat([]byte("synthetic-rootfs"), 64)
	if err := tw.WriteHeader(&tar.Header{Name: "rootfs/control", Mode: 0o600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	plain := compressed.Bytes()
	body, err := decryptWithStaticChaCha20(state, plain)
	if err != nil {
		t.Fatal(err)
	}
	return append(body, bytes.Repeat([]byte{0x5a}, staticChaChaSignatureLen)...), append([]byte(nil), plain...)
}

func syntheticStaticChaChaState() []byte {
	state := make([]byte, staticChaChaStateLen)
	for i := range state {
		state[i] = byte(i + 1)
	}
	return state
}

func TestDecryptRootfsStaticChaCha20(t *testing.T) {
	state := syntheticStaticChaChaState()
	rootfs, want := buildStaticChaChaRootfs(t, state)
	kernel := bytes.Repeat([]byte{0xaa}, 1024)
	const offset = 260
	copy(kernel[offset:], state)

	result, err := DecryptRootfs(context.Background(), kernel, rootfs)
	if err != nil {
		t.Fatalf("DecryptRootfs: %v", err)
	}
	if !bytes.Equal(result.Plaintext, want) {
		t.Fatal("plaintext mismatch")
	}
	if result.Seed.Family != "chacha20-static" || result.Seed.SeedOffset != offset {
		t.Fatalf("selected material = %#v", result.Seed)
	}
	if result.Cipher != "chacha20" {
		t.Fatalf("cipher = %q, want chacha20", result.Cipher)
	}
	if result.HashOK {
		t.Fatal("HashOK = true without a validated signature digest")
	}
	if len(result.Seed.Seed) != 0 || strings.Contains(result.KeyDetail, fmt.Sprintf("%x", state)) {
		t.Fatal("result exposes static ChaCha20 key material")
	}
}

func TestDecryptRootfsStaticChaCha20RejectsMalformedArchive(t *testing.T) {
	state := syntheticStaticChaChaState()
	rootfs, _ := buildStaticChaChaRootfs(t, state)
	rootfs[len(rootfs)-staticChaChaSignatureLen-1] ^= 0x80
	kernel := bytes.Repeat([]byte{0xaa}, 1024)
	copy(kernel[260:], state)

	if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil {
		t.Fatal("expected corrupt gzip trailer to be rejected")
	}
}

func TestDecryptRootfsStaticChaCha20RejectsZeroCandidates(t *testing.T) {
	state := syntheticStaticChaChaState()
	rootfs, _ := buildStaticChaChaRootfs(t, state)
	kernel := bytes.Repeat([]byte{0xaa}, 1024)

	if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil || !strings.Contains(err.Error(), "no aligned static ChaCha20 candidate") {
		t.Fatalf("error = %v, want no static candidate", err)
	}
}

func TestDecryptRootfsStaticChaCha20RejectsMultipleCandidates(t *testing.T) {
	state := syntheticStaticChaChaState()
	rootfs, _ := buildStaticChaChaRootfs(t, state)
	kernel := bytes.Repeat([]byte{0xaa}, 1024)
	copy(kernel[260:], state)
	copy(kernel[520:], state)

	if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil || !strings.Contains(err.Error(), "ambiguous static ChaCha20 material: 2") {
		t.Fatalf("error = %v, want two-candidate ambiguity", err)
	}
}

func TestDecryptRootfsStaticChaCha20RequiresFourByteAlignment(t *testing.T) {
	state := syntheticStaticChaChaState()
	rootfs, _ := buildStaticChaChaRootfs(t, state)
	kernel := bytes.Repeat([]byte{0xaa}, 1024)
	copy(kernel[257:], state)

	if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil || !strings.Contains(err.Error(), "no aligned static ChaCha20 candidate") {
		t.Fatalf("error = %v, want unaligned state rejection", err)
	}
}

func TestStaticChaCha20RejectsMalformedState(t *testing.T) {
	if _, err := decryptWithStaticChaCha20(make([]byte, staticChaChaStateLen-1), []byte("body")); err == nil {
		t.Fatal("expected malformed state length to be rejected")
	}
}

func TestStaticChaCha20CounterCapacity(t *testing.T) {
	state := syntheticStaticChaChaState()
	state[32] = 0xff
	state[33] = 0xff
	state[34] = 0xff
	state[35] = 0xff

	if _, err := decryptWithStaticChaCha20(state, make([]byte, staticChaChaBlockSize)); err != nil {
		t.Fatalf("decrypting final counter block: %v", err)
	}
	if _, err := decryptWithStaticChaCha20(state, make([]byte, staticChaChaBlockSize+1)); err == nil || !strings.Contains(err.Error(), "counter capacity") {
		t.Fatalf("error = %v, want counter-capacity rejection", err)
	}
}

func TestStaticChaCha20GzipTarExpansionLimit(t *testing.T) {
	var tarData bytes.Buffer
	tw := tar.NewWriter(&tarData)
	payload := bytes.Repeat([]byte{0}, 1<<20)
	if err := tw.WriteHeader(&tar.Header{Name: "rootfs/bomb", Mode: 0o600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(tarData.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	if validGzipTarWithin(compressed.Bytes(), int64(tarData.Len()-1)) {
		t.Fatal("accepted gzip tar whose expansion exceeds the validation budget")
	}
	if !validGzipTarWithin(compressed.Bytes(), int64(tarData.Len())) {
		t.Fatal("rejected gzip tar exactly at the validation budget")
	}
}

func TestStaticChaCha20RequiresTarPayload(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write([]byte("not a tar archive")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if validGzipTar(compressed.Bytes()) {
		t.Fatal("accepted a complete gzip member without a tar payload")
	}
}
