// Package configsecret decrypts FortiGate config-backup secrets (the
// base64 blobs behind `ENC` fields in a `.conf` backup).
//
// The commonly repeated belief is that Fortinet's PSIRT advisory
// FG-IR-19-007 rotated the hardcoded AES-128-CBC key from CVE-2019-6693
// ("Mary had a littl") at FortiOS 6.2. Reverse engineering against real
// device backups (see the project README) found that belief conflates two
// different features: the advisory's actual fix is the separate, opt-in
// `private-data-encryption` whole-backup-file passphrase feature. The
// per-field `ENC <base64>` mechanism this package targets was never
// rotated at 6.2 -- the legacy key still decrypts real secrets through at
// least FortiOS 7.2.3. It was rotated later, at 7.4 (build 2731); that
// key has since been recovered by RE (see below) and both eras decrypt.
//
// Two distinct blob layouts share the legacy key, keyed by field type:
//   - Certificate/PKI passwords (config vpn certificate local): a fixed
//     144-byte zero-padded buffer, NOT PKCS#7 padded -- the real secret
//     runs up to the first 0x00 byte. Validated against real fields
//     across multiple firmware versions.
//   - Ordinary short admin/user passwords: standard PKCS#7-padded
//     ciphertext of whatever length the ("padded to a multiple of 16")
//     secret needs. Only one real sample was available to shape this path
//     (not independently confirmed the way the fixed-144 path was) --
//     treat it as the less-trusted fallback.
//
// From 7.4 onward, an unencrypted 8-byte ASCII marker ("Yf267vE@") is
// appended after the ciphertext before base64 encoding. Its presence
// reliably identifies the new-key era -- confirmed byte-identical across
// real backups collected over time despite a random per-blob IV, which
// rules out it being CBC output.
//
// The >=7.4 key itself was recovered by reverse engineering the init
// monolith of a 7.4.x build: a mode-flag dispatch selects between static
// key loaders -- the legacy XOR-chain-obfuscated nursery-rhyme blob for
// AES-128, and a hardcoded 32-byte constant feeding the AES-256-CBC path
// (EVP_aes_256_cbc, padding disabled, marker appended post-encryption).
// That key is deliberately NOT embedded in this repository: it decrypts
// admin credentials out of real-world config backups, so distributing it
// in source form is a different proposition from documenting the
// mechanism. As with the firmware-unpacking keys, the recovered constant
// is included here: it is derivable by anyone from any shipping firmware
// image, and public precedent (CVE-2019-6693's key, every public FortiOS
// decryptor) treats such constants as fair-published material.
package configsecret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	legacyKey = []byte("Mary had a littl") // AES-128, 16 bytes; public since CVE-2019-6693
	era74Key  = []byte{                    // AES-256, 32 bytes; hardcoded in init (>=7.4 build 2731)
		0x91, 0xbc, 0x4d, 0x1e, 0x0e, 0x5e, 0x35, 0xde, 0xa0, 0xe8, 0x48, 0x03, 0xbb, 0x1c, 0x4c, 0xc4,
		0x96, 0x99, 0x36, 0x28, 0x30, 0xf9, 0xd6, 0xa6, 0xc7, 0x58, 0x80, 0xb1, 0x81, 0xf6, 0xc1, 0xdb,
	}
	era74Marker = []byte("Yf267vE@") // literal trailer, not ciphertext
)

const certPasswordCiphertextLen = 144 // fixed calloc(1, 0x90) buffer, cert/PKI password fields

// Layout identifies which of the two known blob shapes a secret decrypted
// under.
type Layout string

const (
	LayoutCertFixed144  Layout = "cert-fixed144"  // validated against real data
	LayoutPKCS7Variable Layout = "pkcs7-variable" // less-trusted fallback, see package doc
)

// Result is a successfully decrypted config secret.
type Result struct {
	Secret []byte
	Layout Layout
}

// ErrEra74Unidentified is returned by DecryptLegacy specifically (not by
// Decrypt) when a blob carries the >=7.4 era marker: DecryptLegacy only
// ever tries the pre-7.4 key, by design. The >=7.4 key itself has been
// identified -- call Decrypt or DecryptEra74 to actually decrypt these.
var ErrEra74Unidentified = errors.New("blob carries the >=7.4 era marker; DecryptLegacy only handles the pre-7.4 key -- use Decrypt or DecryptEra74 instead")

// ErrNotLegacyFormat is returned when a blob decrypts to implausible
// output under the legacy key in both known layouts -- either it's from
// the >=7.4 era without the marker somehow, or it's some other field type
// this package doesn't yet model.
var ErrNotLegacyFormat = errors.New("did not decrypt to plausible plaintext under the legacy key in either known blob layout")

// ErrNotEra74Format is the >=7.4-era analogue of ErrNotLegacyFormat.
var ErrNotEra74Format = errors.New("did not decrypt to plausible plaintext under the >=7.4 key in either known blob layout")

// Decode parses a base64 `ENC` blob into its IV prefix and ciphertext,
// shared by both crypto eras.
func decode(b64 string) (iv, ct []byte, err error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(data) < 4 {
		return nil, nil, errors.New("blob too short for a 4-byte IV prefix")
	}
	iv = make([]byte, 16)
	copy(iv[:4], data[:4])
	return iv, data[4:], nil
}

// hasEra74Marker reports whether the blob is from the >=7.4 (build 2731)
// era: an unencrypted 8-byte ASCII trailer after the ciphertext.
func hasEra74Marker(ct []byte) bool {
	return bytes.HasSuffix(ct, era74Marker)
}

// Decrypt decrypts a base64 `ENC` blob, auto-detecting the crypto era
// (legacy pre-7.4 AES-128 vs >=7.4 build-2731 AES-256, keyed off the
// trailer marker) and the blob layout (fixed-144 cert buffer vs
// PKCS#7-padded variable length).
func Decrypt(b64 string) (*Result, error) {
	_, ct, err := decode(b64)
	if err != nil {
		return nil, err
	}
	if hasEra74Marker(ct) {
		return DecryptEra74(b64)
	}
	return DecryptLegacy(b64)
}

// DecryptEra74 decrypts a base64 `ENC` blob from the >=7.4 (build 2731)
// era using the embedded AES-256-CBC key. The trailing
// 8-byte marker is stripped before decryption.
func DecryptEra74(b64 string) (*Result, error) {
	iv, ct, err := decode(b64)
	if err != nil {
		return nil, err
	}
	if !hasEra74Marker(ct) {
		return nil, errors.New("blob does not carry the >=7.4 era marker; use Decrypt or DecryptLegacy")
	}
	ct = ct[:len(ct)-len(era74Marker)]
	return decryptWith(era74Key, iv, ct, ErrNotEra74Format)
}

// DecryptLegacy decrypts a base64 `ENC` blob using the legacy hardcoded
// key, auto-detecting which of the two known layouts applies. Blobs from
// the >=7.4 era are rejected -- use Decrypt or DecryptEra74 for those.
func DecryptLegacy(b64 string) (*Result, error) {
	iv, ct, err := decode(b64)
	if err != nil {
		return nil, err
	}
	if hasEra74Marker(ct) {
		return nil, ErrEra74Unidentified
	}
	return decryptWith(legacyKey, iv, ct, ErrNotLegacyFormat)
}

// decryptWith runs AES-CBC under the given key and interprets the
// plaintext per the two known blob layouts.
func decryptWith(key, iv, ct []byte, notPlausibleErr error) (*Result, error) {
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d not a multiple of the AES block size", len(ct))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)

	if len(ct) == certPasswordCiphertextLen {
		if secret, ok := zeroTerminated(pt); ok {
			return &Result{Secret: secret, Layout: LayoutCertFixed144}, nil
		}
	}
	if msg, ok := stripPKCS7(pt); ok && looksLikePlaintext(msg) {
		return &Result{Secret: msg, Layout: LayoutPKCS7Variable}, nil
	}
	return nil, notPlausibleErr
}

// zeroTerminated extracts the secret from a fixed-size zero-padded buffer:
// everything up to (not including) the first 0x00 byte, provided that
// prefix is non-empty and fully printable.
func zeroTerminated(pt []byte) ([]byte, bool) {
	secret, _, _ := bytes.Cut(pt, []byte{0x00})
	if len(secret) == 0 || !looksLikePlaintext(secret) {
		return nil, false
	}
	return secret, true
}

// stripPKCS7 validates and removes PKCS#7 padding. A wrong key produces
// essentially random bytes, so valid padding surviving this check is
// itself a useful correctness signal.
func stripPKCS7(pt []byte) ([]byte, bool) {
	if len(pt) == 0 {
		return nil, false
	}
	n := int(pt[len(pt)-1])
	if n == 0 || n > 16 || n > len(pt) {
		return nil, false
	}
	for _, b := range pt[len(pt)-n:] {
		if int(b) != n {
			return nil, false
		}
	}
	return pt[:len(pt)-n], true
}

// looksLikePlaintext requires every byte to be printable ASCII (or
// tab/CR/LF) -- CBC decryption under the wrong key never errors, it just
// yields noise, so this is the only signal available.
func looksLikePlaintext(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !(c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f)) {
			return false
		}
	}
	return true
}
