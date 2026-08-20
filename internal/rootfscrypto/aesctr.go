package rootfscrypto

import "crypto/aes"

// aesCustomCTR implements Fortinet's non-standard AES-CTR, first documented
// by RandoriSec (https://blog.randorisec.fr/fortigate-rootfs-decryption/)
// and noways-io (https://github.com/noways-io/fortigate-crypto) for x86_64:
// a 16-byte counter block (8-byte nonce || 8-byte little-endian counter)
// that increments by a per-image step (XOR of the nibbles of every counter
// byte, minimum 1) instead of by 1. This implementation is verified
// against real FWF-60E 7.4.7/7.4.10/7.4.11 (ARM/FSoC3) images.
func aesCustomCTR(key, nonce8 []byte, counter0 uint64, step uint64, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	c := counter0
	var ctrBlock, ks [16]byte
	copy(ctrBlock[:8], nonce8)
	for off := 0; off < len(data); off += 16 {
		putLE64(ctrBlock[8:16], c)
		block.Encrypt(ks[:], ctrBlock[:])
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		for i := off; i < end; i++ {
			out[i] = data[i] ^ ks[i-off]
		}
		c += step
	}
	return out
}

func putLE64(dst []byte, v uint64) {
	for i := 0; i < 8; i++ {
		dst[i] = byte(v >> (8 * i))
	}
}

// counterStep derives Fortinet's custom CTR increment from the 16-byte
// counter block: XOR of the low and high nibble of every byte, min 1.
func counterStep(counter16 []byte) uint64 {
	step := 0
	for _, b := range counter16 {
		step ^= int(b&0xF) ^ int(b>>4)
	}
	if step == 0 {
		step = 1
	}
	return uint64(step)
}

func getLE64(src []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(src[i]) << (8 * i)
	}
	return v
}
