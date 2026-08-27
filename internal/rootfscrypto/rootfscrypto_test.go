package rootfscrypto

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// These tests build a fully synthetic firmware image in the exact shape
// DecryptRootfs expects -- a kernel payload with an embedded seed+RSA-key
// pair, and a "rootfs.gz" whose trailing signature unwraps to real key
// material -- so the whole auto-detecting pipeline (seed scan, RSA
// unwrap, PKCS#1 parse, body cipher selection) is exercised without
// needing any real Fortinet firmware.

type testRSAKey struct {
	priv *rsa.PrivateKey
	der  []byte // 270-byte PKCS#1 RSAPublicKey DER
}

func genTestRSAKey(t *testing.T) testRSAKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		N *big.Int
		E int
	}{priv.N, priv.E})
	if err != nil {
		t.Fatal(err)
	}
	if len(der) != blobLen {
		t.Fatalf("unexpected DER length %d, want %d (test assumes a standard 2048-bit e=65537 key)", len(der), blobLen)
	}
	return testRSAKey{priv: priv, der: der}
}

// signAsRSAPublicOp signs m with the private key such that rawRSAPublicOp
// (which uses ONLY the public key, mirroring how firmware verifies without
// ever holding the private key) recovers m exactly -- i.e. Fortinet's own
// build-time signing step, reproduced here with a throwaway key.
func signAsRSAPublicOp(m []byte, priv *rsa.PrivateKey) []byte {
	c := new(big.Int).SetBytes(m)
	sig := new(big.Int).Exp(c, priv.D, priv.N)
	modLen := (priv.N.BitLen() + 7) / 8
	out := sig.Bytes()
	if len(out) < modLen {
		padded := make([]byte, modLen)
		copy(padded[modLen-len(out):], out)
		out = padded
	}
	return out
}

func pkcs1Wrap(payload []byte, modLen int) []byte {
	m := make([]byte, modLen)
	m[0] = 0x00
	m[1] = 0x01
	padLen := modLen - 3 - len(payload)
	for i := 0; i < padLen; i++ {
		m[2+i] = 0xFF
	}
	m[2+padLen] = 0x00
	copy(m[3+padLen:], payload)
	return m
}

func embedXORCandidate(t *testing.T, kernel []byte, offset int, key testRSAKey) []byte {
	t.Helper()
	seed := make([]byte, seedLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	copy(kernel[offset:offset+seedLen], seed)
	copy(kernel[offset+seedLen:], xorDecrypt32(seed, key.der))
	return seed
}

func embedChaChaCandidate(t *testing.T, kernel []byte, seedOffset, blobOffset int, key testRSAKey, split [2]int) []byte {
	t.Helper()
	seed := make([]byte, seedLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	copy(kernel[seedOffset:seedOffset+seedLen], seed)
	copy(kernel[blobOffset:blobOffset+blobLen], chacha20Decrypt(seed, split[0], split[1], key.der))
	return seed
}

func buildModifiedRC4Rootfs(t *testing.T, key testRSAKey) ([]byte, []byte) {
	t.Helper()
	plaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte("synthetic-rootfs"), 64)...)
	rc4Key := make([]byte, 32)
	if _, err := rand.Read(rc4Key); err != nil {
		t.Fatal(err)
	}
	body := modifiedRC4(rc4Key, plaintext, false)
	hash := sha256.Sum256(body)
	payload := append(append(append([]byte{}, hash[:]...), make([]byte, 32)...), rc4Key...)
	modLen := (key.priv.N.BitLen() + 7) / 8
	sig := signAsRSAPublicOp(pkcs1Wrap(payload, modLen), key.priv)
	return append(body, sig...), plaintext
}

func buildGzipTar(t *testing.T) []byte {
	t.Helper()
	return gzipBytes(t, buildTar(t))
}

func buildTar(t *testing.T) []byte {
	t.Helper()
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	content := bytes.Repeat([]byte("synthetic-rootfs"), 128)
	if err := tw.WriteHeader(&tar.Header{Name: "bin/init", Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func gzipBytes(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func buildSignedRootfs(t *testing.T, key testRSAKey, body, payload []byte) []byte {
	t.Helper()
	modLen := (key.priv.N.BitLen() + 7) / 8
	sig := signAsRSAPublicOp(pkcs1Wrap(payload, modLen), key.priv)
	return append(append([]byte(nil), body...), sig...)
}

func buildKeyBeforeCounterRootfs(t *testing.T, key testRSAKey, layout string, plaintext, encryptKey, payloadKey, counter []byte, mismatchHash bool) []byte {
	t.Helper()
	body := aesCustomCTR(encryptKey, counter[:8], getLE64(counter[8:16]), counterStep(counter), plaintext)
	hash := sha256.Sum256(body)
	if mismatchHash {
		hash[0] ^= 0xff
	}
	payload := make([]byte, 0, 80)
	switch layout {
	case "prefix":
		payload = append(payload, hash[:]...)
		payload = append(payload, payloadKey...)
		payload = append(payload, counter...)
	case "suffix":
		payload = append(payload, payloadKey...)
		payload = append(payload, counter...)
		payload = append(payload, hash[:]...)
	default:
		t.Fatalf("unknown layout %q", layout)
	}
	return buildSignedRootfs(t, key, body, payload)
}

func aesLayoutMaterial(payload []byte, layout string) ([]byte, []byte) {
	var key, counter []byte
	switch layout {
	case "new-prefix":
		key, counter = payload[32:64], payload[64:80]
	case "new-suffix":
		key, counter = payload[0:32], payload[32:48]
	case "legacy-prefix":
		key, counter = payload[48:80], payload[32:48]
	case "legacy-suffix":
		key, counter = payload[16:48], payload[0:16]
	default:
		panic("unknown AES layout")
	}
	return key, counter
}

func buildOverlappingAESPayload(t *testing.T, first, second string) ([]byte, []byte) {
	t.Helper()
	payload := make([]byte, 80)
	a := bytes.Repeat([]byte{0x11}, 16)
	b := bytes.Repeat([]byte{0x22}, 16)
	switch first + "/" + second {
	case "new-prefix/legacy-prefix":
		copy(payload[32:48], a)
		copy(payload[48:64], a)
		copy(payload[64:80], a)
	case "new-suffix/legacy-suffix":
		copy(payload[0:16], a)
		copy(payload[16:32], a)
		copy(payload[32:48], a)
	case "new-prefix/new-suffix":
		copy(payload[0:16], a)
		copy(payload[16:32], b)
		copy(payload[32:48], a)
		copy(payload[48:64], b)
		copy(payload[64:80], a)
	default:
		t.Fatalf("unsupported overlap %s/%s", first, second)
	}
	firstKey, firstCounter := aesLayoutMaterial(payload, first)
	body := aesCustomCTR(firstKey, firstCounter[:8], getLE64(firstCounter[8:16]), counterStep(firstCounter), buildGzipTar(t))
	secondKey, secondCounter := aesLayoutMaterial(payload, second)
	secondPlain := aesCustomCTR(secondKey, secondCounter[:8], getLE64(secondCounter[8:16]), counterStep(secondCounter), body)
	if !validCompleteGzipTar(secondPlain) {
		t.Fatalf("generated payload does not overlap %s/%s", first, second)
	}
	return body, payload
}

func TestDecryptRootfs_ChaChaFamily_AESCTR(t *testing.T) {
	key := genTestRSAKey(t)

	seed := make([]byte, seedLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	split := chachaKeySplits[0] // (5,2), the FSoC3/ARM finding this repo made
	encBlob := chacha20Decrypt(seed, split[0], split[1], key.der)

	kernelPayload := make([]byte, 4096)
	if _, err := rand.Read(kernelPayload); err != nil {
		t.Fatal(err)
	}
	copy(kernelPayload[512:512+seedLen], seed)
	copy(kernelPayload[512+seedLen:], encBlob)

	// AES-CTR body, ARM ordering: counter(16) | aeskey(32) | hash(32)
	wantPlaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte("rootfs-cpio-data"), 50)...)
	aesKey := make([]byte, 32)
	counter := make([]byte, 16)
	rand.Read(aesKey)
	rand.Read(counter)
	step := counterStep(counter)
	body := aesCustomCTR(aesKey, counter[:8], getLE64(counter[8:16]), step, wantPlaintext)

	hash := sha256.Sum256(body)
	payload := append(append(append([]byte{}, counter...), aesKey...), hash[:]...)
	modLen := (key.priv.N.BitLen() + 7) / 8
	m := pkcs1Wrap(payload, modLen)
	sig := signAsRSAPublicOp(m, key.priv)

	rootfsGz := append(body, sig...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := DecryptRootfs(ctx, kernelPayload, rootfsGz)
	if err != nil {
		t.Fatalf("DecryptRootfs: %v", err)
	}
	if !bytes.Equal(res.Plaintext, wantPlaintext) {
		t.Fatalf("plaintext mismatch: got %d bytes, want %d", len(res.Plaintext), len(wantPlaintext))
	}
	if res.Cipher != "aes-ctr" {
		t.Fatalf("cipher = %q, want aes-ctr", res.Cipher)
	}
	if !res.HashOK {
		t.Fatal("expected HashOK=true")
	}
	if res.Seed.Family != "chacha20" {
		t.Fatalf("family = %q, want chacha20", res.Seed.Family)
	}
}

func TestDecryptRootfs_AESCTRKeyBeforeCounter(t *testing.T) {
	for _, layout := range []string{"prefix", "suffix"} {
		t.Run(layout, func(t *testing.T) {
			key := genTestRSAKey(t)
			kernel := make([]byte, 2048)
			if _, err := rand.Read(kernel); err != nil {
				t.Fatal(err)
			}
			embedXORCandidate(t, kernel, 256, key)
			plaintext := buildGzipTar(t)
			aesKey := make([]byte, 32)
			counter := make([]byte, 16)
			if _, err := rand.Read(aesKey); err != nil {
				t.Fatal(err)
			}
			if _, err := rand.Read(counter); err != nil {
				t.Fatal(err)
			}
			rootfs := buildKeyBeforeCounterRootfs(t, key, layout, plaintext, aesKey, aesKey, counter, false)

			res, err := DecryptRootfs(context.Background(), kernel, rootfs)
			if err != nil {
				t.Fatalf("DecryptRootfs: %v", err)
			}
			if !bytes.Equal(res.Plaintext, plaintext) {
				t.Fatal("plaintext mismatch")
			}
			if res.Cipher != "aes-ctr" || !res.HashOK {
				t.Fatalf("cipher=%q hashOK=%v, want aes-ctr/true", res.Cipher, res.HashOK)
			}
			if !strings.Contains(res.KeyDetail, "layout=") {
				t.Fatalf("missing layout detail: %q", res.KeyDetail)
			}
		})
	}
}

func TestDecryptRootfsRejectsInvalidAESCTRKeyBeforeCounter(t *testing.T) {
	tests := []struct {
		name         string
		mutatePlain  func([]byte) []byte
		wrongKey     bool
		mismatchHash bool
	}{
		{
			name: "corrupt-gzip-crc",
			mutatePlain: func(plaintext []byte) []byte {
				plaintext[len(plaintext)-8] ^= 0xff
				return plaintext
			},
		},
		{
			name: "truncated-gzip",
			mutatePlain: func(plaintext []byte) []byte {
				return plaintext[:len(plaintext)-4]
			},
		},
		{
			name: "trailing-data",
			mutatePlain: func(plaintext []byte) []byte {
				return append(plaintext, 0x42)
			},
		},
		{name: "wrong-key", wrongKey: true},
		{name: "hash-mismatch", mismatchHash: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := genTestRSAKey(t)
			kernel := make([]byte, 2048)
			if _, err := rand.Read(kernel); err != nil {
				t.Fatal(err)
			}
			embedXORCandidate(t, kernel, 256, key)
			plaintext := buildGzipTar(t)
			if test.mutatePlain != nil {
				plaintext = test.mutatePlain(append([]byte(nil), plaintext...))
			}
			encryptKey := make([]byte, 32)
			payloadKey := encryptKey
			counter := make([]byte, 16)
			if _, err := rand.Read(encryptKey); err != nil {
				t.Fatal(err)
			}
			if _, err := rand.Read(counter); err != nil {
				t.Fatal(err)
			}
			if test.wrongKey {
				payloadKey = make([]byte, 32)
				if _, err := rand.Read(payloadKey); err != nil {
					t.Fatal(err)
				}
			}
			rootfs := buildKeyBeforeCounterRootfs(t, key, "prefix", plaintext, encryptKey, payloadKey, counter, test.mismatchHash)
			if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil {
				t.Fatal("expected invalid key-before-counter payload to be rejected")
			}
		})
	}
}

func TestTryAESCTRKeyBeforeCounterRejectsInexactPayloadAndMagicOnly(t *testing.T) {
	plaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte{0x42}, 64)...)
	aesKey := make([]byte, 32)
	counter := make([]byte, 16)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(counter); err != nil {
		t.Fatal(err)
	}
	body := aesCustomCTR(aesKey, counter[:8], getLE64(counter[8:16]), counterStep(counter), plaintext)
	hash := sha256.Sum256(body)
	payload := append(append(append([]byte{}, hash[:]...), aesKey...), counter...)
	if result, handled := tryAESCTRKeyBeforeCounter(payload, body, hash[:]); result != nil || !handled {
		t.Fatalf("magic-only result=%v handled=%v, want nil/true", result, handled)
	}
	if result, handled := tryAESCTRKeyBeforeCounter(append(payload, 0), body, hash[:]); result != nil || !handled {
		t.Fatalf("inexact payload result=%v handled=%v, want nil/true", result, handled)
	}
}

func TestDecryptRootfsRejectsOverlappingNewAESCTRFailures(t *testing.T) {
	tests := []struct {
		name, strictLayout, legacyLayout string
		inexact                          bool
	}{
		{"prefix-hash-mismatch", "new-prefix", "legacy-prefix", false},
		{"suffix-hash-mismatch", "new-suffix", "legacy-suffix", false},
		{"prefix-inexact", "new-prefix", "legacy-prefix", true},
		{"suffix-inexact", "new-suffix", "legacy-suffix", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := genTestRSAKey(t)
			kernel := make([]byte, 2048)
			if _, err := rand.Read(kernel); err != nil {
				t.Fatal(err)
			}
			embedXORCandidate(t, kernel, 256, key)
			body, payload := buildOverlappingAESPayload(t, test.strictLayout, test.legacyLayout)
			digest := sha256.Sum256(body)
			if test.strictLayout == "new-prefix" {
				copy(payload[:32], digest[:])
				if !test.inexact {
					payload[0] ^= 0xff
				}
			} else {
				copy(payload[48:80], digest[:])
				if !test.inexact {
					payload[48] ^= 0xff
				}
			}
			if test.inexact {
				payload = append(payload, 0)
			}
			rootfs := buildSignedRootfs(t, key, body, payload)
			if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil {
				t.Fatal("expected strict AES layout failure to block legacy fallback")
			}
		})
	}
}

func TestDecryptRootfsRejectsIncompleteTarTermination(t *testing.T) {
	complete := buildTar(t)
	if len(complete) < 1024 || !bytes.Equal(complete[len(complete)-1024:], make([]byte, 1024)) {
		t.Fatal("generated tar lacks two zero end records")
	}
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"one-zero-block", gzipBytes(t, complete[:len(complete)-512])},
		{"no-zero-blocks", gzipBytes(t, complete[:len(complete)-1024])},
		{"trailing-bomb", gzipBytes(t, append(append([]byte(nil), complete...), bytes.Repeat([]byte{0x42}, 1<<20)...))},
		{"zero-padding-bomb", gzipBytes(t, append(append([]byte(nil), complete...), make([]byte, 19*512)...))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := genTestRSAKey(t)
			kernel := make([]byte, 2048)
			if _, err := rand.Read(kernel); err != nil {
				t.Fatal(err)
			}
			embedXORCandidate(t, kernel, 256, key)
			aesKey := make([]byte, 32)
			counter := make([]byte, 16)
			if _, err := rand.Read(aesKey); err != nil {
				t.Fatal(err)
			}
			if _, err := rand.Read(counter); err != nil {
				t.Fatal(err)
			}
			rootfs := buildKeyBeforeCounterRootfs(t, key, "prefix", test.plaintext, aesKey, aesKey, counter, false)
			if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil {
				t.Fatal("expected incomplete or trailing tar data to be rejected")
			}
		})
	}
}

func TestDecryptRootfsRejectsAmbiguousAESCTRLayouts(t *testing.T) {
	key := genTestRSAKey(t)
	kernel := make([]byte, 2048)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, key)
	body, payload := buildOverlappingAESPayload(t, "new-prefix", "new-suffix")
	rootfs := buildSignedRootfs(t, key, body, payload)
	if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil {
		t.Fatal("expected ambiguous strict AES layouts to be rejected")
	}
}

func TestDecryptRootfsRejectsAmbiguousAESCTRKeyBeforeCounter(t *testing.T) {
	key := genTestRSAKey(t)
	kernel := make([]byte, 4096)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, key)
	embedXORCandidate(t, kernel, 1024, key)
	plaintext := buildGzipTar(t)
	aesKey := make([]byte, 32)
	counter := make([]byte, 16)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(counter); err != nil {
		t.Fatal(err)
	}
	rootfs := buildKeyBeforeCounterRootfs(t, key, "suffix", plaintext, aesKey, aesKey, counter, false)
	_, err := DecryptRootfs(context.Background(), kernel, rootfs)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous-match error, got %v", err)
	}
}

func TestDecryptRootfsAcceptsAESCTRWithMismatchedBodyHash(t *testing.T) {
	key := genTestRSAKey(t)
	kernel := make([]byte, 2048)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, key)

	wantPlaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte("rootfs-cpio-data"), 50)...)
	aesKey := make([]byte, 32)
	counter := make([]byte, 16)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(counter); err != nil {
		t.Fatal(err)
	}
	body := aesCustomCTR(aesKey, counter[:8], getLE64(counter[8:16]), counterStep(counter), wantPlaintext)

	bodyHash := sha256.Sum256(body)
	bodyHash[0] ^= 0xff
	payload := make([]byte, 0, 80)
	payload = append(payload, bodyHash[:]...)
	payload = append(payload, counter...)
	payload = append(payload, aesKey...)
	modLen := (key.priv.N.BitLen() + 7) / 8
	sig := signAsRSAPublicOp(pkcs1Wrap(payload, modLen), key.priv)

	res, err := DecryptRootfs(context.Background(), kernel, append(body, sig...))
	if err != nil {
		t.Fatalf("DecryptRootfs: %v", err)
	}
	if !bytes.Equal(res.Plaintext, wantPlaintext) {
		t.Fatal("plaintext mismatch")
	}
	if res.Cipher != "aes-ctr" {
		t.Fatalf("cipher = %q, want aes-ctr", res.Cipher)
	}
	if res.HashOK {
		t.Fatal("HashOK = true for a mismatched body hash")
	}
	if res.Seed.SeedOffset != 256 {
		t.Fatalf("selected seed offset = %d, want 256", res.Seed.SeedOffset)
	}
}

func TestDecryptRootfs_XORFamily_ModifiedRC4(t *testing.T) {
	key := genTestRSAKey(t)

	seed := make([]byte, seedLen)
	rand.Read(seed)
	encBlob := xorDecrypt32(seed, key.der) // XOR is its own inverse

	kernelPayload := make([]byte, 4096)
	rand.Read(kernelPayload)
	copy(kernelPayload[1000:1000+seedLen], seed)
	copy(kernelPayload[1000+seedLen:], encBlob)

	wantPlaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte("rootfs-cpio-data"), 50)...)
	rc4Key := make([]byte, 32)
	rand.Read(rc4Key)
	body := modifiedRC4(rc4Key, wantPlaintext, false)

	hash := sha256.Sum256(body)
	// forticrack_v8-style payload: hash(32) | unused(32) | rc4key(32)
	unused := make([]byte, 32)
	rand.Read(unused)
	payload := append(append(append([]byte{}, hash[:]...), unused...), rc4Key...)
	modLen := (key.priv.N.BitLen() + 7) / 8
	m := pkcs1Wrap(payload, modLen)
	sig := signAsRSAPublicOp(m, key.priv)

	rootfsGz := append(body, sig...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := DecryptRootfs(ctx, kernelPayload, rootfsGz)
	if err != nil {
		t.Fatalf("DecryptRootfs: %v", err)
	}
	if !bytes.Equal(res.Plaintext, wantPlaintext) {
		t.Fatalf("plaintext mismatch: got %d bytes, want %d", len(res.Plaintext), len(wantPlaintext))
	}
	if res.Cipher != "modified-rc4" {
		t.Fatalf("cipher = %q, want modified-rc4", res.Cipher)
	}
	if res.Seed.Family != "xor" {
		t.Fatalf("family = %q, want xor", res.Seed.Family)
	}
}

func TestDecryptRootfsAcceptsModifiedRC4WithoutBodyHash(t *testing.T) {
	key := genTestRSAKey(t)
	kernel := make([]byte, 2048)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, key)

	wantPlaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte("rootfs-cpio-data"), 50)...)
	rc4Key := make([]byte, 32)
	if _, err := rand.Read(rc4Key); err != nil {
		t.Fatal(err)
	}
	body := modifiedRC4(rc4Key, wantPlaintext, false)
	modLen := (key.priv.N.BitLen() + 7) / 8
	sig := signAsRSAPublicOp(pkcs1Wrap(rc4Key, modLen), key.priv)

	res, err := DecryptRootfs(context.Background(), kernel, append(body, sig...))
	if err != nil {
		t.Fatalf("DecryptRootfs: %v", err)
	}
	if !bytes.Equal(res.Plaintext, wantPlaintext) {
		t.Fatal("plaintext mismatch")
	}
	if res.HashOK {
		t.Fatal("HashOK = true without a body hash in the signature payload")
	}
}

func TestFindSeedMaterialsNotFound(t *testing.T) {
	junk := bytes.Repeat([]byte{0x11}, 8192)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if materials := FindSeedMaterials(ctx, junk); len(materials) != 0 {
		t.Fatal("expected no seed material to be found in random data")
	}
}

func TestFindSeedMaterialChaChaSeedAtFinalAlignedOffset(t *testing.T) {
	key := genTestRSAKey(t)
	seed := make([]byte, seedLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	split := chachaKeySplits[0]
	encBlob := chacha20Decrypt(seed, split[0], split[1], key.der)

	kernelPayload := make([]byte, 304)
	copy(kernelPayload, encBlob)
	copy(kernelPayload[len(kernelPayload)-seedLen:], seed)

	materials := scanChaChaFamily(context.Background(), kernelPayload)
	if len(materials) != 1 {
		t.Fatalf("found %d seed materials, want 1", len(materials))
	}
	if materials[0].SeedOffset != len(kernelPayload)-seedLen {
		t.Fatalf("seed offset = %d, want %d", materials[0].SeedOffset, len(kernelPayload)-seedLen)
	}
}

func TestFindSeedMaterialsChaChaSplitSixThree(t *testing.T) {
	split := [2]int{6, 3}

	t.Run("contiguous", func(t *testing.T) {
		key := genTestRSAKey(t)
		kernel := make([]byte, 1024)
		embedChaChaCandidate(t, kernel, 128, 160, key, split)

		materials := scanChaChaFamily(context.Background(), kernel)
		if len(materials) != 1 {
			t.Fatalf("found %d seed materials, want 1", len(materials))
		}
		if materials[0].SeedOffset != 128 || materials[0].BlobOffset != 160 ||
			materials[0].KeySplit != 6 || materials[0].IVSplit != 3 {
			t.Fatalf("material = %+v, want seed 128, blob 160, split (6,3)", materials[0])
		}

		plaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte("rootfs-cpio-data"), 50)...)
		body := chacha20Decrypt(materials[0].Seed, split[0], split[1], plaintext)
		if result := tryChaCha20Body(materials[0], body, nil); result != nil {
			t.Fatalf("(6,3) RSA discovery also enabled body probing: %+v", result)
		}
	})

	t.Run("aligned-gap", func(t *testing.T) {
		key := genTestRSAKey(t)
		kernel := make([]byte, 1024)
		embedChaChaCandidate(t, kernel, 544, 256, key, split)

		materials := scanChaChaFamily(context.Background(), kernel)
		if len(materials) != 1 {
			t.Fatalf("found %d seed materials, want 1", len(materials))
		}
		if materials[0].SeedOffset != 544 || materials[0].BlobOffset != 256 {
			t.Fatalf("offsets = (%d,%d), want (544,256)", materials[0].SeedOffset, materials[0].BlobOffset)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		key := genTestRSAKey(t)
		kernel := make([]byte, 1024)
		seed := embedChaChaCandidate(t, kernel, 128, 160, key, split)
		malformed := append([]byte(nil), key.der...)
		malformed[len(malformed)-1] ^= 0xff
		copy(kernel[160:160+blobLen], chacha20Decrypt(seed, split[0], split[1], malformed))

		if materials := scanChaChaFamily(context.Background(), kernel); len(materials) != 0 {
			t.Fatalf("found %d seed materials, want 0", len(materials))
		}
	})

	t.Run("zero", func(t *testing.T) {
		if materials := scanChaChaFamily(context.Background(), make([]byte, 1024)); len(materials) != 0 {
			t.Fatalf("found %d seed materials, want 0", len(materials))
		}
	})

	t.Run("multiple", func(t *testing.T) {
		first := genTestRSAKey(t)
		second := genTestRSAKey(t)
		kernel := make([]byte, 2048)
		if _, err := rand.Read(kernel); err != nil {
			t.Fatal(err)
		}
		embedChaChaCandidate(t, kernel, 128, 160, first, split)
		embedChaChaCandidate(t, kernel, 1536, 1024, second, split)

		materials := scanChaChaFamily(context.Background(), kernel)
		if len(materials) != 2 {
			t.Fatalf("found %d seed materials, want 2", len(materials))
		}
	})
}

func TestFindSeedMaterialsDeterministicOrder(t *testing.T) {
	first := genTestRSAKey(t)
	second := genTestRSAKey(t)
	kernel := make([]byte, 4096)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 1024, second)
	embedXORCandidate(t, kernel, 256, first)

	for i := 0; i < 2; i++ {
		materials := FindSeedMaterials(context.Background(), kernel)
		if len(materials) != 2 {
			t.Fatalf("scan %d found %d candidates, want 2", i, len(materials))
		}
		if materials[0].SeedOffset != 256 || materials[1].SeedOffset != 1024 {
			t.Fatalf("scan %d offsets = [%d, %d], want [256, 1024]",
				i, materials[0].SeedOffset, materials[1].SeedOffset)
		}
		material := FindSeedMaterial(context.Background(), kernel)
		if material == nil || material.SeedOffset != 256 {
			t.Fatalf("FindSeedMaterial = %v, want seed offset 256", material)
		}
	}
}

// TestDecryptRootfs_ChaCha20Body covers the 7.4.1-7.4.3 era: the body is
// ChaCha20-encrypted with key/IV derived by rotated-SHA256 of the seed
// (Optistream fortigate-crypto scheme: key = SHA256(seed[4:]+seed[:4]),
// iv = SHA256(seed[5:]+seed[:5])), rather than AES-CTR from the signature.
func TestDecryptRootfs_ChaCha20Body(t *testing.T) {
	key := genTestRSAKey(t)

	seed := make([]byte, seedLen)
	rand.Read(seed)
	// RSA key obfuscated with a different split than the body derivation,
	// as observed on real builds
	encBlob := chacha20Decrypt(seed, 2, 3, key.der)

	kernelPayload := make([]byte, 4096)
	rand.Read(kernelPayload)
	copy(kernelPayload[512:512+seedLen], seed)
	copy(kernelPayload[512+seedLen:], encBlob)

	wantPlaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte("rootfs-cpio-data"), 50)...)

	// body cipher: key split 4, iv split 5 (the fortigate-crypto finding)
	body := chacha20Decrypt(seed, 4, 5, wantPlaintext)

	hash := sha256.Sum256(body)
	payload := hash[:] // era-appropriate: signature carries just the hash
	modLen := (key.priv.N.BitLen() + 7) / 8
	m := pkcs1Wrap(payload, modLen)
	sig := signAsRSAPublicOp(m, key.priv)

	rootfsGz := append(body, sig...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := DecryptRootfs(ctx, kernelPayload, rootfsGz)
	if err != nil {
		t.Fatalf("DecryptRootfs: %v", err)
	}
	if !bytes.Equal(res.Plaintext, wantPlaintext) {
		t.Fatalf("plaintext mismatch: got %d bytes", len(res.Plaintext))
	}
	if res.Cipher != "chacha20" {
		t.Fatalf("cipher = %q, want chacha20", res.Cipher)
	}
}

func TestDecryptRootfsSelectsSignatureMatchingCandidate(t *testing.T) {
	wrong := genTestRSAKey(t)
	correct := genTestRSAKey(t)
	kernel := make([]byte, 4096)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, wrong)
	embedXORCandidate(t, kernel, 1024, correct)
	rootfs, plaintext := buildModifiedRC4Rootfs(t, correct)

	res, err := DecryptRootfs(context.Background(), kernel, rootfs)
	if err != nil {
		t.Fatalf("DecryptRootfs: %v", err)
	}
	if res.Seed.SeedOffset != 1024 {
		t.Fatalf("selected seed offset = %d, want 1024", res.Seed.SeedOffset)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("selected candidate produced the wrong plaintext")
	}
}

func TestDecryptRootfsRejectsIncorrectKey(t *testing.T) {
	embedded := genTestRSAKey(t)
	signer := genTestRSAKey(t)
	kernel := make([]byte, 2048)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, embedded)
	rootfs, _ := buildModifiedRC4Rootfs(t, signer)
	if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil {
		t.Fatal("expected incorrect embedded key to be rejected")
	}
}

func TestDecryptRootfsRejectsMalformedSignature(t *testing.T) {
	key := genTestRSAKey(t)
	kernel := make([]byte, 2048)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, key)
	rootfs, _ := buildModifiedRC4Rootfs(t, key)
	rootfs[len(rootfs)-1] ^= 0x80
	if _, err := DecryptRootfs(context.Background(), kernel, rootfs); err == nil {
		t.Fatal("expected malformed signature to be rejected")
	}
}

func TestDecryptRootfsRejectsSignatureAtModulus(t *testing.T) {
	key := genTestRSAKey(t)
	kernel := make([]byte, 2048)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, key)
	body := bytes.Repeat([]byte{0x42}, 1024)
	sig := key.priv.N.FillBytes(make([]byte, key.priv.Size()))
	if _, err := DecryptRootfs(context.Background(), kernel, append(body, sig...)); err == nil {
		t.Fatal("expected a signature equal to the modulus to be rejected")
	}
}

func TestDecryptRootfsRejectsInvalidPKCS1Padding(t *testing.T) {
	key := genTestRSAKey(t)
	kernel := make([]byte, 2048)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, key)
	body := bytes.Repeat([]byte{0x42}, 1024)
	message := make([]byte, 256)
	message[0], message[1], message[2], message[3] = 0, 1, 0xff, 0
	sig := signAsRSAPublicOp(message, key.priv)
	if _, err := DecryptRootfs(context.Background(), kernel, append(body, sig...)); err == nil {
		t.Fatal("expected short PKCS#1 padding to be rejected")
	}
}

func TestDecryptRootfsRejectsAmbiguousMatches(t *testing.T) {
	key := genTestRSAKey(t)
	kernel := make([]byte, 4096)
	if _, err := rand.Read(kernel); err != nil {
		t.Fatal(err)
	}
	embedXORCandidate(t, kernel, 256, key)
	embedXORCandidate(t, kernel, 1024, key)
	rootfs, _ := buildModifiedRC4Rootfs(t, key)
	_, err := DecryptRootfs(context.Background(), kernel, rootfs)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous-match error, got %v", err)
	}
}

func TestDecryptRootfsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DecryptRootfs(ctx, make([]byte, 1<<20), make([]byte, 512))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestPKCS1UnwrapRejectsMissingAndShortPadding(t *testing.T) {
	for name, message := range map[string][]byte{
		"missing-terminator": append([]byte{0, 1}, bytes.Repeat([]byte{0xff}, 16)...),
		"seven-byte-padding": append(append([]byte{0, 1}, bytes.Repeat([]byte{0xff}, 7)...), 0, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pkcs1Unwrap(message); err == nil {
				t.Fatal("expected invalid padding to be rejected")
			}
		})
	}
	valid := append(append([]byte{0, 1}, bytes.Repeat([]byte{0xff}, 8)...), 0, 1)
	if payload, err := pkcs1Unwrap(valid); err != nil || !bytes.Equal(payload, []byte{1}) {
		t.Fatalf("expected eight-byte padding to be accepted, payload=%x err=%v", payload, err)
	}
}

func TestTryAESCTRReportsMismatchedBodyHash(t *testing.T) {
	payload := make([]byte, 80)
	for i := range payload {
		payload[i] = byte(i*37 + 11)
	}
	plaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte{0x42}, 64)...)
	body := aesCustomCTR(payload[48:80], payload[32:40], getLE64(payload[40:48]), counterStep(payload[32:48]), plaintext)
	bodyHash := bytes.Repeat([]byte{0x42}, sha256.Size)
	if _, handled := tryAESCTRKeyBeforeCounter(payload, body, bodyHash); handled {
		t.Fatal("legacy fixture is structurally ambiguous with a strict layout")
	}
	result, handled := tryAESCTR(payload, body, bodyHash)
	if result == nil || !handled {
		t.Fatal("expected a plausible AES plaintext despite the mismatched body hash")
	}
	if result.HashOK {
		t.Fatal("HashOK = true for a mismatched body hash")
	}
}
