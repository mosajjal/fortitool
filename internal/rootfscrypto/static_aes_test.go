package rootfscrypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"testing"

	"github.com/ulikunitz/xz"
)

func staticAESFixture(t *testing.T, newc []byte) (kernel, encrypted, plain []byte) {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(newc); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	plain = buf.Bytes()
	kernel = make([]byte, 512)
	copy(kernel, "\x7fELF")
	copy(kernel[128:], "AES test key!!!!")
	copy(kernel[144:], "test counter!!!!")
	encrypted = encryptStaticAES(t, kernel[128:160], plain)
	return
}

func encryptStaticAES(t *testing.T, state, plain []byte) []byte {
	t.Helper()
	b, err := aes.NewCipher(state[:16])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(plain))
	cipher.NewCTR(b, state[16:]).XORKeyStream(out, plain)
	digest := sha256.Sum256(plain)
	return append(out, digest[:]...)
}

func TestStaticAESCTRRootfs(t *testing.T) {
	kernel, enc, plain := staticAESFixture(t, buildNewc(t))
	res, err := DecryptRootfs(context.Background(), kernel, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.Plaintext, plain) || !res.HashOK || res.Cipher != "aes-128-ctr" || res.Seed.Family != "aes-static" {
		t.Fatal("incorrect static AES result")
	}
	copy(kernel[252:284], kernel[128:160])
	clear(kernel[128:160])
	if _, err := DecryptRootfs(context.Background(), kernel, enc); err != nil {
		t.Fatalf("relocated material: %v", err)
	}
}

func TestStaticAESCTRRejectsInvalidCandidates(t *testing.T) {
	for _, kind := range []string{"key", "digest", "ciphertext", "truncated", "xz-trailer", "missing-cpio-trailer", "tail", "ambiguous", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			newc := buildNewc(t)
			if kind == "missing-cpio-trailer" {
				newc = newc[:len(newc)-124]
			}
			kernel, enc, plain := staticAESFixture(t, newc)
			ctx := context.Background()
			switch kind {
			case "key":
				kernel[128] ^= 1
			case "digest":
				enc[len(enc)-1] ^= 1
			case "ciphertext":
				enc[20] ^= 1
			case "truncated":
				enc = enc[:len(enc)-1]
			case "xz-trailer":
				plain[len(plain)-4] ^= 1
				enc = encryptStaticAES(t, kernel[128:160], plain)
			case "tail":
				enc = encryptStaticAES(t, kernel[128:160], append(plain, 1))
			case "ambiguous":
				copy(kernel[256:], kernel[128:160])
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			res, err := decryptStaticAESCTR(ctx, kernel, enc)
			if res != nil || (kind == "cancelled" && err == nil) {
				t.Fatal("invalid candidate accepted")
			}
		})
	}
}

func TestStaticAESXZExpandedLimit(t *testing.T) {
	newc := buildNewc(t)
	_, _, plain := staticAESFixture(t, newc)
	if !validStaticAESRootfs(context.Background(), plain, int64(len(newc))) {
		t.Fatal("exact limit rejected")
	}
	if validStaticAESRootfs(context.Background(), plain, int64(len(newc)-1)) {
		t.Fatal("expansion limit exceeded")
	}
}
