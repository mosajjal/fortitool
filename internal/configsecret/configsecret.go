// Package configsecret decrypts FortiGate config-backup secrets (the
// base64 blobs behind `ENC` fields in a `.conf` backup).
//
// The legacy key and blob layout are from gquere's CVE-2019-6693 disclosure
// and reference decryptor (https://github.com/gquere/CVE-2019-6693). The
// commonly repeated belief is that Fortinet's PSIRT advisory FG-IR-19-007
// rotated that hardcoded AES-128-CBC key ("Mary had a littl") at FortiOS
// 6.2. Reverse engineering against real
// device backups (see the project README) found that belief conflates two
// different features: the advisory's actual fix is the separate, opt-in
// `private-data-encryption` whole-backup-file passphrase feature. The
// per-field `ENC <base64>` mechanism this package targets was never
// rotated at 6.2 -- the legacy key still decrypts real secrets through at
// least FortiOS 7.2.3. It was rotated later, at 7.4 (build 2731), to a key
// that has not been identified.
//
// Two distinct blob layouts share the legacy key, keyed by field type:
//   - Certificate/PKI passwords (config vpn certificate local): a fixed
//     144-byte zero-padded buffer, NOT PKCS#7 padded -- the real secret
//     runs up to the first 0x00 byte. Validated against 22 real fields
//     across three firmware versions.
//   - Ordinary short admin/user passwords: standard PKCS#7-padded
//     ciphertext of whatever length the ("padded to a multiple of 16")
//     secret needs. Only one real sample was available to shape this path
//     (not independently confirmed the way the fixed-144 path was) --
//     treat it as the less-trusted fallback.
//
// From 7.4 onward, an unencrypted 8-byte ASCII marker ("Yf267vE@") is
// appended after the ciphertext before base64 encoding. Its presence
// reliably identifies the new, unidentified-key era -- confirmed
// byte-identical across 9 real backups spanning two months despite a
// random per-blob IV, which rules out it being CBC output.
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
	legacyKey   = []byte("Mary had a littl") // AES-128, 16 bytes
	era74Marker = []byte("Yf267vE@")         // literal trailer, not ciphertext
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

// ErrEra74Unidentified is returned when the blob carries the >=7.4 trailer
// marker: the legacy key is known NOT to apply here, and the real key
// hasn't been identified yet, so no decrypt is attempted.
var ErrEra74Unidentified = errors.New("blob carries the >=7.4 era marker; that era's key has not been identified (legacy key confirmed not to apply)")

// ErrNotLegacyFormat is returned when a blob decrypts to implausible
// output under the legacy key in both known layouts -- either it's from
// the >=7.4 era without the marker somehow, or it's some other field type
// this package doesn't yet model.
var ErrNotLegacyFormat = errors.New("did not decrypt to plausible plaintext under the legacy key in either known blob layout")

// DecryptLegacy decrypts a base64 `ENC` blob using the legacy hardcoded
// key, auto-detecting which of the two known layouts applies.
func DecryptLegacy(b64 string) (*Result, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(data) < 4 {
		return nil, errors.New("blob too short for a 4-byte IV prefix")
	}
	iv := make([]byte, 16)
	copy(iv[:4], data[:4])
	ct := data[4:]

	if bytes.HasSuffix(ct, era74Marker) {
		return nil, ErrEra74Unidentified
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d not a multiple of the AES block size", len(ct))
	}

	block, err := aes.NewCipher(legacyKey)
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
	return nil, ErrNotLegacyFormat
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
