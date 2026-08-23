// Package rootfscrypto locates and reverses the rootfs.gz encryption used
// across FortiOS 7.4.x-8.0: a 32-byte seed plus a 270-byte obfuscated
// RSAPublicKey DER blob hidden somewhere in the kernel (flatkc), used to
// unwrap a per-image AES/RC4 key carried in rootfs.gz's trailing signature.
//
// Two obfuscation families are known, and this package auto-detects both
// without any disassembly (miasm/objdump), by exploiting that the blob
// always decrypts to a known ASN.1 DER prefix:
//   - XOR family (7.6.x aarch64, 8.0 FORT-RC4): blob[i] ^ seed[i&0x1F]
//   - ChaCha20 family (7.4.1-7.4.11, ARM+x86): key/iv = SHA256 of seed with
//     one of several observed byte-rotation splits
package rootfscrypto

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"sync"

	"golang.org/x/crypto/chacha20"
)

const (
	seedLen = 32
	blobLen = 270
)

// derPrefix8 is the first 8 bytes every recovered RSAPublicKey DER must
// start with: SEQUENCE(0x010a) { INTEGER(0x0101) 0x00 ... }.
var derPrefix8 = [8]byte{0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01}

// derSuffix5 is the standard public exponent 65537 encoded as the trailing
// ASN.1 INTEGER, present at the end of every 270-byte blob we've observed.
var derSuffix5 = [5]byte{0x02, 0x03, 0x01, 0x00, 0x01}

// chachaSplits are the seed byte-rotation splits (key-split, iv-split)
// observed across FortiOS builds/architectures (RandoriSec, fgx, and this
// repo's own FSoC3/ARM finding of (5,2)).
var chachaSplits = [][2]int{{5, 2}, {4, 5}, {3, 1}, {5, 5}, {2, 5}, {1, 3}, {3, 2}, {4, 2}, {5, 3}, {2, 3}}

// SeedMaterial is a located, decrypted seed+RSA-key pair.
type SeedMaterial struct {
	Seed       []byte
	SeedOffset int
	BlobOffset int
	Family     string // "xor" or "chacha20"
	KeySplit   int    // chacha20 family only
	IVSplit    int    // chacha20 family only
	DER        []byte
	Key        *RSAPublicKey
}

func rotSHA256(seed []byte, split int) []byte {
	h := sha256.New()
	h.Write(seed[split:])
	h.Write(seed[:split])
	return h.Sum(nil)
}

func chacha20Keystream(seed []byte, keySplit, ivSplit int, n int) []byte {
	key := rotSHA256(seed, keySplit)
	iv := rotSHA256(seed, ivSplit)[:16]
	var nonce [12]byte
	copy(nonce[:], iv[4:16])
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce[:])
	if err != nil {
		return nil
	}
	counter := binary.LittleEndian.Uint32(iv[:4])
	c.SetCounter(counter)
	dst := make([]byte, n)
	c.XORKeyStream(dst, make([]byte, n))
	return dst
}

func chacha20Decrypt(seed []byte, keySplit, ivSplit int, data []byte) []byte {
	ks := chacha20Keystream(seed, keySplit, ivSplit, len(data))
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ ks[i]
	}
	return out
}

func xorDecrypt32(seed, enc []byte) []byte {
	out := make([]byte, len(enc))
	for i := range enc {
		out[i] = enc[i] ^ seed[i&0x1F]
	}
	return out
}

func validDER(der []byte) bool {
	if len(der) != blobLen {
		return false
	}
	for i, b := range derPrefix8 {
		if der[i] != b {
			return false
		}
	}
	for i, b := range derSuffix5 {
		if der[blobLen-5+i] != b {
			return false
		}
	}
	key, err := parsePKCS1PublicKey(der)
	if err != nil {
		return false
	}
	_ = key
	return true
}

func lowEntropySeed(seed []byte) bool {
	seen := map[byte]bool{}
	for _, b := range seed {
		seen[b] = true
	}
	return len(seen) < 8
}

// scanXORFamily tries the 7.6.x/8.0-style obfuscation: seed contiguous with
// blob, or seed within 512 bytes of blob (RSA-key-first layout, as in
// forticrack_v8's fixed x86_64 offsets and fgx's aarch64 near-contiguous
// case).
func scanXORFamily(data []byte) *SeedMaterial {
	// Pass 1: contiguous seed(32) + blob(270)
	for off := 0; off+seedLen+blobLen <= len(data); off++ {
		seed := data[off : off+seedLen]
		if lowEntropySeed(seed) {
			continue
		}
		enc := data[off+seedLen : off+seedLen+blobLen]
		if enc[0]^seed[0] != derPrefix8[0] || enc[1]^seed[1] != derPrefix8[1] {
			continue
		}
		der := xorDecrypt32(seed, enc)
		if !validDER(der) {
			continue
		}
		key, err := parsePKCS1PublicKey(der)
		if err != nil {
			continue
		}
		return &SeedMaterial{
			Seed: append([]byte(nil), seed...), SeedOffset: off,
			BlobOffset: off + seedLen, Family: "xor", DER: der, Key: key,
		}
	}

	// Pass 2: near-contiguous, blob (RSA key) precedes seed within 512 bytes
	// (forticrack_v8's x86_64 8.0 layout: RSA_ENC_VA < XOR_KEY_VA, gap 0x120).
	idx := map[[2]byte][]int{}
	for off := 0; off+blobLen <= len(data); off++ {
		k := [2]byte{data[off], data[off+1]}
		idx[k] = append(idx[k], off)
	}
	for off := 0; off+seedLen <= len(data); off++ {
		seed := data[off : off+seedLen]
		if lowEntropySeed(seed) {
			continue
		}
		want := [2]byte{seed[0] ^ derPrefix8[0], seed[1] ^ derPrefix8[1]}
		for _, blobOff := range idx[want] {
			if blobOff == off+seedLen {
				continue // already covered by pass 1
			}
			dist := blobOff - off
			if dist < 0 {
				dist = -dist
			}
			if dist > 512 || dist < seedLen {
				continue
			}
			enc := data[blobOff : blobOff+blobLen]
			der := xorDecrypt32(seed, enc)
			if !validDER(der) {
				continue
			}
			key, err := parsePKCS1PublicKey(der)
			if err != nil {
				continue
			}
			return &SeedMaterial{
				Seed: append([]byte(nil), seed...), SeedOffset: off,
				BlobOffset: blobOff, Family: "xor", DER: der, Key: key,
			}
		}
	}
	return nil
}

// scanChaChaFamily locates a contiguous seed(32)+blob(270) pair whose blob
// decrypts under ChaCha20 (for some known seed-rotation split) to a valid
// RSAPublicKey DER. Disassembly-free: indexes candidate windows by the
// 8-byte ChaCha20 keystream prefix a correct seed would need to produce,
// then scans seed candidates for a match (same trick as this repo's
// fwf_find_crypto_material.py, generalized across all known splits).
func scanChaChaFamily(ctx context.Context, data []byte) *SeedMaterial {
	if len(data) < blobLen {
		return nil
	}
	type winKey [8]byte
	wanted := map[winKey][]int{}
	for off := 0; off+blobLen <= len(data); off += 4 {
		var k winKey
		for i := 0; i < 8; i++ {
			k[i] = data[off+i] ^ derPrefix8[i]
		}
		wanted[k] = append(wanted[k], off)
	}

	numSeedOffsets := (len(data)-seedLen)/4 + 1
	if numSeedOffsets <= 0 {
		return nil
	}

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	result := make(chan *SeedMaterial, 1)
	var wg sync.WaitGroup
	chunk := (numSeedOffsets + workers - 1) / workers

	for w := 0; w < workers; w++ {
		startIdx := w * chunk
		endIdx := startIdx + chunk
		if startIdx >= numSeedOffsets {
			break
		}
		if endIdx > numSeedOffsets {
			endIdx = numSeedOffsets
		}
		wg.Add(1)
		go func(startIdx, endIdx int) {
			defer wg.Done()
			for i := startIdx; i < endIdx; i++ {
				select {
				case <-subCtx.Done():
					return
				default:
				}
				off := i * 4
				seed := data[off : off+seedLen]
				if lowEntropySeed(seed) {
					continue
				}
				for _, split := range chachaSplits {
					var k winKey
					copy(k[:], chacha20Keystream(seed, split[0], split[1], 8))
					blobOffs, ok := wanted[k]
					if !ok {
						continue
					}
					for _, blobOff := range blobOffs {
						enc := data[blobOff : blobOff+blobLen]
						der := chacha20Decrypt(seed, split[0], split[1], enc)
						if !validDER(der) {
							continue
						}
						key, err := parsePKCS1PublicKey(der)
						if err != nil {
							continue
						}
						sm := &SeedMaterial{
							Seed: append([]byte(nil), seed...), SeedOffset: off,
							BlobOffset: blobOff, Family: "chacha20",
							KeySplit: split[0], IVSplit: split[1], DER: der, Key: key,
						}
						select {
						case result <- sm:
							cancel()
						default:
						}
						return
					}
				}
			}
		}(startIdx, endIdx)
	}

	go func() {
		wg.Wait()
		close(result)
	}()
	return <-result
}

// FindSeedMaterial runs both scan families (XOR fast path first, since it's
// cheap; ChaCha20 fallback covers 7.4.x) and returns whichever locates valid
// crypto material in the given kernel payload.
func FindSeedMaterial(ctx context.Context, kernelPayload []byte) *SeedMaterial {
	if sm := scanXORFamily(kernelPayload); sm != nil {
		return sm
	}
	return scanChaChaFamily(ctx, kernelPayload)
}
