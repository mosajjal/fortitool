package rootfscrypto

import (
	"encoding/asn1"
	"errors"
	"math/big"
)

// RSAPublicKey is the PKCS#1 RSAPublicKey ASN.1 structure Fortinet embeds
// (XOR- or ChaCha20-obfuscated) in every rootfs-encrypting kernel.
type RSAPublicKey struct {
	N *big.Int
	E int
}

// parsePKCS1PublicKey decodes a DER RSAPublicKey (SEQUENCE{INTEGER N, INTEGER E}).
func parsePKCS1PublicKey(der []byte) (*RSAPublicKey, error) {
	var key struct {
		N *big.Int
		E int
	}
	rest, err := asn1.Unmarshal(der, &key)
	if err != nil {
		return nil, err
	}
	_ = rest
	if key.N == nil || key.N.Sign() <= 0 {
		return nil, errors.New("invalid modulus")
	}
	bits := key.N.BitLen()
	if bits < 1024 || bits > 8192 {
		return nil, errors.New("implausible RSA key size")
	}
	if key.E < 3 || key.E > (1<<31-1) {
		return nil, errors.New("implausible RSA exponent")
	}
	return &RSAPublicKey{N: key.N, E: key.E}, nil
}

// rawRSAPublicOp computes sig^e mod n (the "public key operation" Fortinet
// uses to unwrap the trailing rootfs signature with its own public key,
// since it never needs the private key on-device).
func rawRSAPublicOp(sig []byte, key *RSAPublicKey) []byte {
	c := new(big.Int).SetBytes(sig)
	e := big.NewInt(int64(key.E))
	m := new(big.Int).Exp(c, e, key.N)
	modLen := (key.N.BitLen() + 7) / 8
	out := m.Bytes()
	if len(out) < modLen {
		padded := make([]byte, modLen)
		copy(padded[modLen-len(out):], out)
		out = padded
	}
	return out
}
