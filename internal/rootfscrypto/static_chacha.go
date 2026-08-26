package rootfscrypto

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
)

const (
	staticChaChaStateLen     = 48
	staticChaChaAlignment    = 4
	staticChaChaSignatureLen = 256
	staticChaChaBlockSize    = 64
	staticChaChaMaxExpanded  = int64(4 << 30)
)

// Optistream's Apache-2.0 fortigate-crypto implementation documents this
// family as key(32)+counter/nonce(16) and excludes a trailing 256-byte
// signature from the encrypted body.
func decryptStaticChaCha20(ctx context.Context, kernelPayload, rootfsGz []byte) (*Result, error) {
	if len(rootfsGz) < staticChaChaSignatureLen+3 {
		return nil, fmt.Errorf("no seed/RSA-key material found and rootfs is too short for static ChaCha20 validation")
	}
	body := rootfsGz[:len(rootfsGz)-staticChaChaSignatureLen]
	matches := make([]*Result, 0, 1)

	for off := 0; off+staticChaChaStateLen <= len(kernelPayload); off += staticChaChaAlignment {
		if off&0xfff == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}
		state := kernelPayload[off : off+staticChaChaStateLen]
		probe, err := decryptWithStaticChaCha20(state, body[:3])
		if err != nil || !bytes.Equal(probe, []byte{0x1f, 0x8b, 0x08}) {
			continue
		}
		plain, err := decryptWithStaticChaCha20(state, body)
		if err != nil || !validGzipTar(plain) {
			continue
		}
		matches = append(matches, &Result{
			Plaintext: plain,
			Seed: &SeedMaterial{
				SeedOffset: off,
				BlobOffset: -1,
				Family:     "chacha20-static",
			},
			Cipher:    "chacha20",
			HashOK:    false,
			KeyDetail: "static ChaCha20 state (not displayed)",
		})
	}

	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, fmt.Errorf("no seed/RSA-key material found; no aligned static ChaCha20 candidate passed complete gzip/tar validation")
	default:
		return nil, fmt.Errorf("ambiguous static ChaCha20 material: %d aligned candidates passed complete gzip/tar validation", len(matches))
	}
}

func decryptWithStaticChaCha20(state, data []byte) ([]byte, error) {
	if len(state) != staticChaChaStateLen {
		return nil, fmt.Errorf("invalid static ChaCha20 state length %d", len(state))
	}
	key := state[:32]
	counterNonce := state[32:]
	counter := binary.LittleEndian.Uint32(counterNonce[:4])
	blocks := (uint64(len(data)) + staticChaChaBlockSize - 1) / staticChaChaBlockSize
	if uint64(counter)+blocks > 1<<32 {
		return nil, fmt.Errorf("static ChaCha20 body exceeds counter capacity")
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key, counterNonce[4:])
	if err != nil {
		return nil, err
	}
	cipher.SetCounter(counter)
	plain := make([]byte, len(data))
	cipher.XORKeyStream(plain, data)
	return plain, nil
}

func validGzipTar(data []byte) bool {
	return validGzipTarWithin(data, staticChaChaMaxExpanded)
}

func validGzipTarWithin(data []byte, maxExpanded int64) bool {
	if maxExpanded < 0 {
		return false
	}
	compressed := bytes.NewReader(data)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return false
	}
	gz.Multistream(false)
	// Match the CLI's 4 GiB rootfs expansion ceiling while validating each
	// candidate, so a magic-matching candidate cannot consume unbounded work or
	// be selected when the downstream rootfs command would reject it.
	expanded := &io.LimitedReader{R: gz, N: maxExpanded + 1}
	tr := tar.NewReader(expanded)
	entries := 0
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = gz.Close()
			return false
		}
		entries++
		if _, err := io.Copy(io.Discard, tr); err != nil {
			_ = gz.Close()
			return false
		}
	}
	if _, err := io.Copy(io.Discard, expanded); err != nil {
		_ = gz.Close()
		return false
	}
	if expanded.N == 0 {
		_ = gz.Close()
		return false
	}
	if err := gz.Close(); err != nil {
		return false
	}
	return entries != 0 && compressed.Len() == 0
}
