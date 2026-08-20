package rootfscrypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
)

var gzipMagic = []byte{0x1f, 0x8b}

// Result carries everything the caller might want to log/verify about a
// successful rootfs decryption.
type Result struct {
	Plaintext []byte // decrypted rootfs.gz (still gzip-compressed cpio)
	Seed      *SeedMaterial
	Cipher    string // "aes-ctr" or "fort-rc4" or "modified-rc4"
	HashOK    bool   // SHA-256(body) matched the value carried in the signature
	KeyDetail string
}

// DecryptRootfs is the full auto-detecting rootfs.gz decryption pipeline:
// locate seed+RSA key in the kernel payload (any known family/split), RSA-
// unwrap the trailing signature, then try every known body-cipher layout
// until one produces a valid gzip stream.
func DecryptRootfs(ctx context.Context, kernelPayload, rootfsGz []byte) (*Result, error) {
	sm := FindSeedMaterial(ctx, kernelPayload)
	if sm == nil {
		return nil, fmt.Errorf("no seed/RSA-key material found in kernel payload (%d bytes)", len(kernelPayload))
	}

	modLen := (sm.Key.N.BitLen() + 7) / 8
	if len(rootfsGz) <= modLen {
		return nil, fmt.Errorf("rootfs.gz too small (%d bytes) for a %d-byte signature", len(rootfsGz), modLen)
	}
	body := rootfsGz[:len(rootfsGz)-modLen]
	sig := rootfsGz[len(rootfsGz)-modLen:]

	m := rawRSAPublicOp(sig, sm.Key)
	payload, err := pkcs1Unwrap(m)
	if err != nil {
		return nil, fmt.Errorf("RSA signature unwrap failed: %w", err)
	}

	bodyHash := sha256.Sum256(body)

	if r := tryAESCTR(payload, body, bodyHash[:]); r != nil {
		r.Seed = sm
		return r, nil
	}
	if r := tryStreamCiphers(payload, body, bodyHash[:]); r != nil {
		r.Seed = sm
		return r, nil
	}

	return nil, fmt.Errorf("recovered RSA key (family=%s) but no known body cipher (AES-CTR / FORT-RC4 / modified-RC4) produced a valid gzip stream", sm.Family)
}

// tryAESCTR handles the two known field orderings of the AES-CTR signature
// payload: [hash|counter|aes_key] (x86_64, fgx) and [counter|aes_key|hash]
// (ARM FSoC3, this repo).
func tryAESCTR(payload, body, bodyHash []byte) *Result {
	if len(payload) < 80 {
		return nil
	}
	type layout struct {
		name              string
		hash, ctr, aeskey []byte
	}
	layouts := []layout{
		{"hash|counter|aeskey", payload[0:32], payload[32:48], payload[48:80]},
		{"counter|aeskey|hash", payload[48:80], payload[0:16], payload[16:48]},
	}
	for _, l := range layouts {
		hashOK := bytes.Equal(l.hash, bodyHash)
		step := counterStep(l.ctr)
		nonce := l.ctr[:8]
		counter0 := getLE64(l.ctr[8:16])
		plain := aesCustomCTR(l.aeskey, nonce, counter0, step, body)
		if len(plain) >= 2 && plain[0] == gzipMagic[0] && plain[1] == gzipMagic[1] {
			return &Result{
				Plaintext: plain, Cipher: "aes-ctr", HashOK: hashOK,
				KeyDetail: fmt.Sprintf("layout=%s aes_key=%x", l.name, l.aeskey),
			}
		}
	}
	return nil
}

// tryStreamCiphers handles FORT-RC4 (8.0, both FGT/FFW silicon variants)
// and 7.6.x's distinct modified-RC4, auto-detecting which by trying each
// against the first bytes of the body and checking for the gzip magic. Key
// material is the trailing 32 bytes of the PKCS#1 payload in every observed
// layout, regardless of what sits between the hash and the key.
func tryStreamCiphers(payload, body, bodyHash []byte) *Result {
	if len(payload) < 32 {
		return nil
	}
	key := payload[len(payload)-32:]
	hashOK := bytes.Contains(payload, bodyHash)

	probeLen := 64
	if probeLen > len(body) {
		probeLen = len(body)
	}
	probe := body[:probeLen]

	type candidate struct {
		name string
		fn   func([]byte, []byte) []byte
	}
	candidates := []candidate{
		{"fort-rc4 (FGT)", func(k, d []byte) []byte { return fortRC4(k, d, true) }},
		{"fort-rc4 (FFW)", func(k, d []byte) []byte { return fortRC4(k, d, false) }},
		{"modified-rc4 (reset-j)", func(k, d []byte) []byte { return modifiedRC4(k, d, false) }},
		{"modified-rc4 (keep-j)", func(k, d []byte) []byte { return modifiedRC4(k, d, true) }},
	}

	for _, c := range candidates {
		out := c.fn(key, probe)
		if len(out) >= 2 && out[0] == gzipMagic[0] && out[1] == gzipMagic[1] {
			full := c.fn(key, body)
			cipherName := "fort-rc4"
			if c.name[0] == 'm' {
				cipherName = "modified-rc4"
			}
			return &Result{
				Plaintext: full, Cipher: cipherName, HashOK: hashOK,
				KeyDetail: fmt.Sprintf("variant=%s key=%x", c.name, key),
			}
		}
	}
	return nil
}
