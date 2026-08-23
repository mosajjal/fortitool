package rootfscrypto

import "errors"

// pkcs1Unwrap strips a PKCS#1 v1.5 Type-1 signature envelope
// (0x00 0x01 0xFF* 0x00 <payload>) from a raw RSA public-key operation
// result and returns the payload. Every FortiOS rootfs-signature layout
// observed (ARM FSoC3 "crypto_ctx" struct, x86_64 AES-CTR, RC4/FORT-RC4)
// turns out to be this same envelope with a different payload shape inside.
func pkcs1Unwrap(m []byte) ([]byte, error) {
	if len(m) < 4 || m[0] != 0x00 || m[1] != 0x01 {
		return nil, errors.New("not a PKCS#1 v1.5 Type-1 signature")
	}
	i := 2
	for i < len(m) && m[i] == 0xFF {
		i++
	}
	if i-2 < 8 {
		return nil, errors.New("PKCS#1 Type-1 padding is shorter than 8 bytes")
	}
	if i >= len(m) || m[i] != 0x00 {
		return nil, errors.New("missing PKCS#1 padding terminator")
	}
	return m[i+1:], nil
}
