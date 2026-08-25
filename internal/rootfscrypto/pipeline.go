package rootfscrypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
)

var (
	gzipMagic = []byte{0x1f, 0x8b}
	xzMagic   = []byte("\xfd7zXZ\x00")
)

// plausibleBody reports whether b starts like a compressed stream we can
// handle downstream. FortiOS <= 7.6 rootfs bodies are gzip; FortiOS 8.0
// VM images carry an xz-compressed ext4 rootfs instead.
func plausibleBody(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	if b[0] == gzipMagic[0] && b[1] == gzipMagic[1] {
		return true
	}
	return bytes.Equal(b[:6], xzMagic)
}

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
// locate seed+RSA candidates in the kernel payload, select a candidate through
// signature-envelope and body validation, then decrypt with the matching body
// cipher.
func DecryptRootfs(ctx context.Context, kernelPayload, rootfsGz []byte) (*Result, error) {
	candidates := FindSeedMaterials(ctx, kernelPayload)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no seed/RSA-key material found in kernel payload (%d bytes)", len(kernelPayload))
	}

	var matches []*Result
	validEnvelopes := 0
	for _, sm := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, envelopeOK := decryptRootfsCandidate(sm, rootfsGz)
		if envelopeOK {
			validEnvelopes++
		}
		if result != nil {
			matches = append(matches, result)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, fmt.Errorf("%d seed/RSA-key candidates found; %d valid signature envelopes, but no candidate passed supported body validation", len(candidates), validEnvelopes)
	default:
		return nil, fmt.Errorf("ambiguous rootfs crypto material: %d of %d candidates passed signature and body validation", len(matches), len(candidates))
	}
}

func decryptRootfsCandidate(sm *SeedMaterial, rootfsGz []byte) (*Result, bool) {
	modLen := (sm.Key.N.BitLen() + 7) / 8
	if len(rootfsGz) <= modLen {
		return nil, false
	}
	body := rootfsGz[:len(rootfsGz)-modLen]
	sig := rootfsGz[len(rootfsGz)-modLen:]
	if new(big.Int).SetBytes(sig).Cmp(sm.Key.N) >= 0 {
		return nil, false
	}

	m := rawRSAPublicOp(sig, sm.Key)
	payload, err := pkcs1Unwrap(m)
	if err != nil {
		return nil, false
	}

	bodyHash := sha256.Sum256(body)

	if r := tryAESCTR(payload, body, bodyHash[:]); r != nil {
		r.Seed = sm
		return r, true
	}
	if r := tryChaCha20Body(sm, body, bodyHash[:]); r != nil {
		r.Seed = sm
		return r, true
	}
	if r := tryStreamCiphers(payload, body, bodyHash[:]); r != nil {
		r.Seed = sm
		return r, true
	}

	return nil, true
}

// tryChaCha20Body handles the 7.4.1-7.4.3 era (Bishop Fox "Further
// Adventures", Optistream fortigate-crypto): the rootfs body itself is
// ChaCha20-encrypted with key = SHA256(rot_k(seed)) and 16-byte IV =
// SHA256(rot_i(seed)), the counter being the first IV word (Fortinet's
// non-RFC7539 layout). The exact rotation split varies by build, so every
// known split is tried against a probe until the gzip/xz magic appears.
func tryChaCha20Body(sm *SeedMaterial, body, bodyHash []byte) *Result {
	probeLen := 64
	if probeLen > len(body) {
		probeLen = len(body)
	}
	for _, split := range chachaSplits {
		ks := chacha20Keystream(sm.Seed, split[0], split[1], probeLen)
		probe := make([]byte, probeLen)
		for i := range probe {
			probe[i] = body[i] ^ ks[i]
		}
		if !plausibleBody(probe) {
			continue
		}
		full := chacha20Decrypt(sm.Seed, split[0], split[1], body)
		// In this era the body hash inside the RSA payload is BER-encoded,
		// so a raw byte comparison isn't possible; HashOK stays false and
		// the gzip/xz magic + downstream decompression are the checks.
		return &Result{
			Plaintext: full, Cipher: "chacha20", HashOK: false,
			KeyDetail: fmt.Sprintf("body-key-split=%d body-iv-split=%d seed=%x",
				split[0], split[1], sm.Seed),
		}
	}
	return nil
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
		if plausibleBody(plain) {
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
		if plausibleBody(out) {
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
