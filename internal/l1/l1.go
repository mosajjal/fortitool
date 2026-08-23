// Package l1 implements Fortinet's outer ".out" firmware image cipher: a
// 512-byte-block XOR chain with a 32-byte alphanumeric key, IV=0xFF reset at
// every block boundary. Identical scheme from FortiOS 6.x through 8.0 (Bishop
// Fox's forticrack, verbatim-reused by forticrack_v8 and fgx). The key is
// recovered live via a known-plaintext attack (32 NUL bytes at block offset
// 48) rather than looked up in a table, so no fixed key list is needed.
package l1

import (
	"context"
	"runtime"
	"sync"
)

const (
	BlockSize         = 512
	headerSize        = 80
	knownPlaintextOff = 48
)

// magics accepted at cleartext-header offset 12..15. Both endiannesses are
// seen across product lines (mosajjal/forticrack fork finding).
var magics = [][4]byte{
	{0xff, 0x00, 0xaa, 0x55},
	{0x55, 0xaa, 0x00, 0xff},
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func validKey(key []byte) bool {
	if len(key) != 32 {
		return false
	}
	for _, b := range key {
		if !isAlnum(b) {
			return false
		}
	}
	return true
}

// validateDecryption reports whether cleartext looks like a decrypted
// firmware header: magic at [12:16] and an ASCII image name at [16:46]
// containing "build".
func validateDecryption(cleartext []byte) bool {
	if len(cleartext) < 46 {
		return false
	}
	m := cleartext[12:16]
	matched := false
	for _, magic := range magics {
		if m[0] == magic[0] && m[1] == magic[1] && m[2] == magic[2] && m[3] == magic[3] {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	name := cleartext[16:46]
	for _, b := range name {
		if b == 0 {
			continue
		}
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	lower := make([]byte, len(name))
	for i, b := range name {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		lower[i] = b
	}
	return containsBuild(lower)
}

func containsBuild(s []byte) bool {
	needle := []byte("build")
	if len(s) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(s); i++ {
		match := true
		for j := range needle {
			if s[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// IsCleartext reports whether data already carries a valid, unencrypted
// firmware header at block 0 offset 0..79 (some images ship unencrypted).
func IsCleartext(data []byte) bool {
	for off := 0; off+headerSize <= len(data); off += BlockSize {
		if validateDecryption(data[off : off+headerSize]) {
			return true
		}
		if off == 0 && len(data) < BlockSize {
			break
		}
	}
	return false
}

// decryptBlock decrypts up to BlockSize bytes of a single 512-byte block.
// State (IV=0xFF, key offset=0) resets at the start of every call, matching
// Fortinet's per-block chaining.
func decryptBlock(ciphertext, key []byte) []byte {
	n := len(ciphertext)
	if n > BlockSize {
		n = BlockSize
	}
	out := make([]byte, n)
	prev := byte(0xFF)
	keyOff := 0
	for i := 0; i < n; i++ {
		ct := ciphertext[i]
		out[i] = (prev ^ ct ^ key[keyOff]) - byte(keyOff)
		prev = ct
		keyOff = (keyOff + 1) & 0x1F
	}
	return out
}

// deriveKeyFromHeader attempts the known-plaintext attack against one
// block's 80-byte header (32 NUL bytes assumed at offset 48..79) and
// validates the recovered key by decrypting the header itself.
func deriveKeyFromHeader(header []byte) []byte {
	if len(header) < headerSize {
		return nil
	}
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		keyOffset := (i + 16) % 32
		po := i + knownPlaintextOff
		key[i] = header[po-1] ^ header[po] ^ byte(keyOffset)
	}
	swapped := make([]byte, 32)
	copy(swapped[:16], key[16:])
	copy(swapped[16:], key[:16])
	if !validKey(swapped) {
		return nil
	}
	cleartext := decryptBlock(header, swapped)
	if !validateDecryption(cleartext) {
		return nil
	}
	return swapped
}

// DeriveKey scans every 512-byte block of data for a validated key via the
// known-plaintext attack, using all CPUs, and returns as soon as any block
// yields one (Fortinet reuses one key across the whole image).
func DeriveKey(ctx context.Context, data []byte) []byte {
	numBlocks := (len(data) + BlockSize - 1) / BlockSize
	if numBlocks == 0 {
		return nil
	}
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan int, workers*2)
	results := make(chan []byte, 1)
	var wg sync.WaitGroup

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for blockNum := range jobs {
				select {
				case <-subCtx.Done():
					return
				default:
				}
				off := blockNum * BlockSize
				end := off + headerSize
				if end > len(data) {
					continue
				}
				if key := deriveKeyFromHeader(data[off:end]); key != nil {
					select {
					case results <- key:
						cancel()
					default:
					}
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for b := 0; b < numBlocks; b++ {
			select {
			case <-subCtx.Done():
				return
			case jobs <- b:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return <-results
}

// Decrypt decrypts an entire image using a recovered 32-byte key, one
// 512-byte block at a time, in parallel.
func Decrypt(data, key []byte) []byte {
	if len(key) != 32 {
		return nil
	}
	numBlocks := (len(data) + BlockSize - 1) / BlockSize
	out := make([]byte, len(data))
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	blocksPerWorker := (numBlocks + workers - 1) / workers
	for w := 0; w < workers; w++ {
		start := w * blocksPerWorker
		end := start + blocksPerWorker
		if start >= numBlocks {
			break
		}
		if end > numBlocks {
			end = numBlocks
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for b := start; b < end; b++ {
				off := b * BlockSize
				blockEnd := off + BlockSize
				if blockEnd > len(data) {
					blockEnd = len(data)
				}
				plain := decryptBlock(data[off:blockEnd], key)
				copy(out[off:blockEnd], plain)
			}
		}(start, end)
	}
	wg.Wait()
	return out
}

// DecryptAuto is the full L1 pipeline: detects cleartext, otherwise derives
// the key live and decrypts. Returns (plaintext, key, wasEncrypted).
func DecryptAuto(ctx context.Context, data []byte) (plaintext, key []byte, wasEncrypted bool, ok bool) {
	if IsCleartext(data) {
		return data, nil, false, true
	}
	key = DeriveKey(ctx, data)
	if key == nil {
		return nil, nil, true, false
	}
	return Decrypt(data, key), key, true, true
}
