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

func TestDecryptLegacyEra74Marker(t *testing.T) {
	buf := make([]byte, certPasswordCiphertextLen)
	copy(buf, []byte("some-secret-encrypted-under-the-unidentified-post-7.4-key"))
	b64, ivPrefix := encryptLegacyForTest(t, buf)

	// The marker is appended AFTER encryption, unencrypted -- reconstruct
	// that shape directly rather than via encryptLegacyForTest.
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	_ = ivPrefix
	withMarker := append(raw, era74Marker...)
	b64WithMarker := base64.StdEncoding.EncodeToString(withMarker)

	_, err = DecryptLegacy(b64WithMarker)
	if !errors.Is(err, ErrEra74Unidentified) {
		t.Fatalf("got err=%v, want ErrEra74Unidentified", err)
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
