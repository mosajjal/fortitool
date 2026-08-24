package configsecret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
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

func encryptEra74ForTest(t *testing.T, ct []byte) string {
	t.Helper()
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
	out := make([]byte, len(ct))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, ct)
	raw := append(append(ivPrefix, out...), era74Marker...)
	return base64.StdEncoding.EncodeToString(raw)
}

// TestDecryptEra74CertFixed144 exercises the >=7.4 (build 2731) AES-256
// path with the recovered key, in the fixed-144 cert-password layout that
// was validated against all 26 real new-format blobs.
func TestDecryptEra74CertFixed144(t *testing.T) {
	secret := []byte("feedface0011223344556677889900aabbccddeeff00112233445566778899")
	buf := make([]byte, certPasswordCiphertextLen)
	copy(buf, secret)

	b64 := encryptEra74ForTest(t, buf)
	res, err := Decrypt(b64)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(res.Secret) != string(secret) {
		t.Fatalf("got %q want %q", res.Secret, secret)
	}
	if res.Layout != LayoutCertFixed144 {
		t.Fatalf("layout = %q, want %q", res.Layout, LayoutCertFixed144)
	}
}

// TestDecryptEra74PKCS7Variable covers the short admin-password shape
// under the new key.
func TestDecryptEra74PKCS7Variable(t *testing.T) {
	secret := []byte("guest")
	padded := append(append([]byte{}, secret...), makePadding(aes.BlockSize-len(secret)%aes.BlockSize)...)

	b64 := encryptEra74ForTest(t, padded)
	res, err := Decrypt(b64)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(res.Secret) != string(secret) {
		t.Fatalf("got %q want %q", res.Secret, secret)
	}
	if res.Layout != LayoutPKCS7Variable {
		t.Fatalf("layout = %q, want %q", res.Layout, LayoutPKCS7Variable)
	}
}

// TestDecryptAutoDetectsLegacy makes sure the era-dispatching entry point
// still routes pre-7.4 blobs to the legacy key.
func TestDecryptAutoDetectsLegacy(t *testing.T) {
	buf := make([]byte, certPasswordCiphertextLen)
	copy(buf, []byte("abc123"))
	b64, _ := encryptLegacyForTest(t, buf)

	res, err := Decrypt(b64)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(res.Secret) != "abc123" {
		t.Fatalf("got %q", res.Secret)
	}
}

// TestDecryptEra74RejectsNonMarker checks the explicit-era entry point
// refuses blobs without the trailer.
func TestDecryptEra74RejectsNonMarker(t *testing.T) {
	buf := make([]byte, certPasswordCiphertextLen)
	b64, _ := encryptLegacyForTest(t, buf)
	if _, err := DecryptEra74(b64); err == nil {
		t.Fatal("expected error for a blob without the era marker")
	}
}

func TestDecryptEra74RejectsMalformedCiphertextWithoutPanic(t *testing.T) {
	entrypoints := map[string]func(string) (*Result, error){
		"auto":     Decrypt,
		"explicit": DecryptEra74,
	}
	for _, ciphertextLen := range []int{0, 1, 15, 17, 31} {
		ciphertextLen := ciphertextLen
		blob := append(make([]byte, 4), bytes.Repeat([]byte{0xA5}, ciphertextLen)...)
		blob = append(blob, era74Marker...)
		b64 := base64.StdEncoding.EncodeToString(blob)

		for name, decrypt := range entrypoints {
			t.Run(fmt.Sprintf("%s/length-%d", name, ciphertextLen), func(t *testing.T) {
				_, err := decryptNoPanic(t, decrypt, b64)
				if err == nil || !strings.Contains(err.Error(), "ciphertext length") {
					t.Fatalf("err = %v, want ciphertext-length error", err)
				}
			})
		}
	}
}

func decryptNoPanic(t *testing.T, decrypt func(string) (*Result, error), b64 string) (res *Result, err error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("decrypt panicked: %v", recovered)
		}
	}()
	return decrypt(b64)
}

func FuzzDecryptNoPanic(f *testing.F) {
	for _, ciphertextLen := range []int{0, 1, 15, 16, 17, 31, 32} {
		blob := append(make([]byte, 4), bytes.Repeat([]byte{0xA5}, ciphertextLen)...)
		f.Add(base64.StdEncoding.EncodeToString(append(blob, era74Marker...)))
	}
	f.Add("")
	f.Add("not-valid-base64!!!")

	f.Fuzz(func(t *testing.T, b64 string) {
		_, _ = Decrypt(b64)
		_, _ = DecryptEra74(b64)
		_, _ = DecryptLegacy(b64)
	})
}

// TestEra74KeyShape pins the recovered key's length -- a silent truncation
// here would fail as implausible-plaintext rather than a key error.
func TestEra74KeyShape(t *testing.T) {
	if len(era74Key) != 32 {
		t.Fatalf("era74Key length = %d, want 32 (AES-256)", len(era74Key))
	}
}
