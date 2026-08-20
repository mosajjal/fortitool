package rootfscrypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
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

func TestFindSeedMaterialNotFound(t *testing.T) {
	junk := bytes.Repeat([]byte{0x11}, 8192)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if sm := FindSeedMaterial(ctx, junk); sm != nil {
		t.Fatal("expected no seed material to be found in random data")
	}
}
