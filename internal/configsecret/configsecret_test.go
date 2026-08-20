package configsecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func encryptLegacyForTest(t *testing.T, ct []byte) (b64 string, ivPrefix []byte) {
	t.Helper()
	ivPrefix = make([]byte, 4)
	if _, err := rand.Read(ivPrefix); err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	copy(iv[:4], ivPrefix)

	block, err := aes.NewCipher(legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(ct))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, ct)
	return base64.StdEncoding.EncodeToString(append(append([]byte{}, ivPrefix...), out...)), ivPrefix
}

// TestDecryptLegacyCertFixed144 exercises the validated real-world path:
// a fixed 144-byte zero-padded buffer, no PKCS7, secret ends at the first
// NUL byte (the certificate/PKI password field encoding).
func TestDecryptLegacyCertFixed144(t *testing.T) {
	secret := []byte("d34db33f0011223344556677889900aabbccddeeff00112233445566778899")
	buf := make([]byte, certPasswordCiphertextLen)
	copy(buf, secret) // rest stays zero, matching the real calloc'd buffer

	b64, _ := encryptLegacyForTest(t, buf)
	res, err := DecryptLegacy(b64)
	if err != nil {
		t.Fatalf("DecryptLegacy: %v", err)
	}
	if string(res.Secret) != string(secret) {
		t.Fatalf("got %q want %q", res.Secret, secret)
	}
	if res.Layout != LayoutCertFixed144 {
		t.Fatalf("layout = %q, want %q", res.Layout, LayoutCertFixed144)
	}
}

// TestDecryptLegacyPKCS7Variable exercises the less-trusted fallback path
// for ordinary short admin/user passwords.
func TestDecryptLegacyPKCS7Variable(t *testing.T) {
	secret := []byte("guest")
	padLen := aes.BlockSize - len(secret)%aes.BlockSize
	padded := append(append([]byte{}, secret...), makePadding(padLen)...)

	b64, _ := encryptLegacyForTest(t, padded)
	res, err := DecryptLegacy(b64)
	if err != nil {
		t.Fatalf("DecryptLegacy: %v", err)
	}
	if string(res.Secret) != string(secret) {
		t.Fatalf("got %q want %q", res.Secret, secret)
	}
	if res.Layout != LayoutPKCS7Variable {
		t.Fatalf("layout = %q, want %q", res.Layout, LayoutPKCS7Variable)
	}
}

func makePadding(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(n)
	}
	return p
}

func TestDecryptEra74WrongKeyRejected(t *testing.T) {
	// A marker blob whose ciphertext was produced under the WRONG key
	// (legacy AES-128 here) must not silently "decrypt" -- it should fall
	// through both era-7.4 layout checks to ErrNotLegacyFormat.
	buf := make([]byte, certPasswordCiphertextLen)
	copy(buf, []byte("encrypted-under-the-legacy-key-but-marked-as-era-7.4"))
	b64, _ := encryptLegacyForTest(t, buf)

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	withMarker := append(raw, era74Marker...)
	_, err = DecryptLegacy(base64.StdEncoding.EncodeToString(withMarker))
	if !errors.Is(err, ErrNotLegacyFormat) {
		t.Fatalf("got err=%v, want ErrNotLegacyFormat", err)
	}
}

func TestDecryptEra74CertFixed144(t *testing.T) {
	// >=7.4 (build 2731) era: AES-256-CBC under the new hardcoded key,
	// same 4-byte IV prefix, fixed 144-byte zero-padded buffer, and the
	// unencrypted 8-byte marker appended after the ciphertext.
	secret := []byte("464608dd30a23635d7b889a246163f4c3cd29b4d33f7eca8ff4d11895c9f95")
	buf := make([]byte, certPasswordCiphertextLen)
	copy(buf, secret)

	ivPrefix := make([]byte, 4)
	if _, err := rand.Read(ivPrefix); err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	copy(iv[:4], ivPrefix)
	block, err := aes.NewCipher(era74Key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(buf))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, buf)

	raw := append(append([]byte{}, ivPrefix...), out...)
	raw = append(raw, era74Marker...)
	res, err := DecryptLegacy(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("DecryptLegacy (era-7.4 blob): %v", err)
	}
	if string(res.Secret) != string(secret) {
		t.Fatalf("got %q want %q", res.Secret, secret)
	}
	if res.Layout != LayoutCertFixed144 {
		t.Fatalf("layout = %q, want %q", res.Layout, LayoutCertFixed144)
	}
}

func TestDecryptEra74PKCS7Variable(t *testing.T) {
	// Real-world shape observed for short admin passwords in >=7.4
	// backups (e.g. the factory 'guest' default admin).
	secret := []byte("guest")
	padded := append(append([]byte{}, secret...), makePadding(aes.BlockSize-len(secret)%aes.BlockSize)...)

	ivPrefix := make([]byte, 4)
	if _, err := rand.Read(ivPrefix); err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	copy(iv[:4], ivPrefix)
	block, err := aes.NewCipher(era74Key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)

	raw := append(append([]byte{}, ivPrefix...), out...)
	raw = append(raw, era74Marker...)
	res, err := DecryptLegacy(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("DecryptLegacy (era-7.4 blob): %v", err)
	}
	if string(res.Secret) != string(secret) {
		t.Fatalf("got %q want %q", res.Secret, secret)
	}
	if res.Layout != LayoutPKCS7Variable {
		t.Fatalf("layout = %q, want %q", res.Layout, LayoutPKCS7Variable)
	}
}

func TestDecryptLegacyWrongKeyDetected(t *testing.T) {
	// Random bytes decrypt to garbage under the legacy key in both
	// layouts; the heuristics should reject it rather than claim success.
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	blob := base64.StdEncoding.EncodeToString(raw)
	_, err := DecryptLegacy(blob)
	if !errors.Is(err, ErrNotLegacyFormat) {
		t.Fatalf("got err=%v, want ErrNotLegacyFormat", err)
	}
}

func TestDecryptLegacyBadBase64(t *testing.T) {
	if _, err := DecryptLegacy("not-valid-base64!!!"); err == nil {
		t.Fatal("expected an error for invalid base64")
	}
}
