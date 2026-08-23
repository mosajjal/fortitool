package l1

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

// encryptBlockForTest is the inverse of decryptBlock, built directly from
// the documented per-byte relation so tests can construct ciphertext
// without depending on any real firmware sample.
func encryptBlockForTest(plaintext, key []byte) []byte {
	n := len(plaintext)
	if n > BlockSize {
		n = BlockSize
	}
	out := make([]byte, n)
	prev := byte(0xFF)
	keyOff := 0
	for i := 0; i < n; i++ {
		ct := (plaintext[i] + byte(keyOff)) ^ key[keyOff] ^ prev
		out[i] = ct
		prev = ct
		keyOff = (keyOff + 1) & 0x1F
	}
	return out
}

func buildFakeImage(t *testing.T, key []byte, magic [4]byte, numBlocks int) []byte {
	t.Helper()
	plain := make([]byte, numBlocks*BlockSize)
	// header block: magic @12..15, name @16..45 containing "build"
	copy(plain[12:16], magic[:])
	copy(plain[16:46], []byte("FWF60E-v7.4.7-FW-build2731-xx"))
	// plain[48:80] must stay zero -- that's the known-plaintext region the
	// attack keys off (see l1.go's derive-key comment); fill everything
	// after it with non-zero pattern data instead.
	for i := 80; i < len(plain); i++ {
		plain[i] = byte(i * 7 % 256)
	}
	ct := make([]byte, len(plain))
	for b := 0; b < numBlocks; b++ {
		off := b * BlockSize
		copy(ct[off:off+BlockSize], encryptBlockForTest(plain[off:off+BlockSize], key))
	}
	return ct
}

func TestDecryptAutoRoundTrip(t *testing.T) {
	key := []byte("abcdefghij0123456789ABCDEFGHIJKL") // 32 alnum bytes
	ct := buildFakeImage(t, key, [4]byte{0xff, 0x00, 0xaa, 0x55}, 4)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	plain, gotKey, wasEncrypted, ok := DecryptAuto(ctx, ct)
	if !ok {
		t.Fatal("DecryptAuto failed to find a key")
	}
	if !wasEncrypted {
		t.Fatal("expected wasEncrypted=true")
	}
	if !bytes.Equal(gotKey, key) {
		t.Fatalf("key mismatch: got %q want %q", gotKey, key)
	}
	if plain[12] != 0xff || plain[13] != 0x00 || plain[14] != 0xaa || plain[15] != 0x55 {
		t.Fatalf("decrypted header magic wrong: % x", plain[12:16])
	}
}

func TestDecryptAutoBigEndianMagic(t *testing.T) {
	key := []byte("Z9Y8X7W6V5U4T3S2R1Q0PoNmLkJiHgFe")
	ct := buildFakeImage(t, key, [4]byte{0x55, 0xaa, 0x00, 0xff}, 2)

	ctx := context.Background()
	_, gotKey, _, ok := DecryptAuto(ctx, ct)
	if !ok {
		t.Fatal("DecryptAuto failed on BE-magic image")
	}
	if !bytes.Equal(gotKey, key) {
		t.Fatalf("key mismatch: got %q want %q", gotKey, key)
	}
}

func TestIsCleartext(t *testing.T) {
	plain := make([]byte, BlockSize)
	copy(plain[12:16], []byte{0xff, 0x00, 0xaa, 0x55})
	copy(plain[16:46], []byte("FWF60E-v7.4.7-FW-build2731-xxxx"))
	if !IsCleartext(plain) {
		t.Fatal("expected cleartext image to be detected as cleartext")
	}

	junk := bytes.Repeat([]byte{0x42}, BlockSize)
	if IsCleartext(junk) {
		t.Fatal("random junk should not be detected as cleartext")
	}
}

func TestDecryptAutoNoKeyFound(t *testing.T) {
	junk := bytes.Repeat([]byte{0x7a}, BlockSize*3)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _, ok := DecryptAuto(ctx, junk)
	if ok {
		t.Fatal("expected no key to be found in random data")
	}
}

func TestDecryptRejectsInvalidKeyLengths(t *testing.T) {
	data := make([]byte, BlockSize)
	for _, n := range []int{0, 31, 33} {
		t.Run(fmt.Sprintf("length_%d", n), func(t *testing.T) {
			if got := Decrypt(data, make([]byte, n)); got != nil {
				t.Fatalf("Decrypt returned %d bytes for a %d-byte key", len(got), n)
			}
		})
	}
}
