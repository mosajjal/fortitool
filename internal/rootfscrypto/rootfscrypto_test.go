package rootfscrypto

import (
	"bytes"
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

func TestDecryptRootfs_ChaChaFamily_AESCTR(t *testing.T) {
	key := genTestRSAKey(t)

	seed := make([]byte, seedLen)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	split := chachaSplits[0] // (5,2), the FSoC3/ARM finding this repo made
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
	split := chachaSplits[0]
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

func TestTryAESCTRRequiresMatchingBodyHash(t *testing.T) {
	payload := make([]byte, 80)
	plaintext := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte{0x42}, 64)...)
	body := aesCustomCTR(payload[48:80], payload[32:40], 0, counterStep(payload[32:48]), plaintext)
	bodyHash := bytes.Repeat([]byte{0x42}, sha256.Size)
	if result := tryAESCTR(payload, body, bodyHash); result != nil {
		t.Fatalf("accepted AES layout with mismatched body hash: %+v", result)
	}
}
