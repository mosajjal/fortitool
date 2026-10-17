package rootfscrypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"math"

	"github.com/mosajjal/fortitool/internal/archive"
	"github.com/ulikunitz/xz"
)

// Rapid7 and Bishop Fox document adjacent AES-128 key/IV material and the
// standard big-endian CTR increment in FortiManager's forti_decrypt:
// https://www.rapid7.com/blog/post/ra-cve-2024-47575-analysis/
// https://bishopfox.com/blog/a-look-at-fortijump-cve-2024-47575
// The observed FAZ/FMG body ends in an unencrypted SHA-256 of the XZ plaintext.
func decryptStaticAESCTR(ctx context.Context, kernel, rootfs []byte) (*Result, error) {
	if len(rootfs) < sha256.Size+aes.BlockSize {
		return nil, nil
	}
	body, digest := rootfs[:len(rootfs)-sha256.Size], rootfs[len(rootfs)-sha256.Size:]
	var match *Result
	var probe [aes.BlockSize]byte
	for off := 0; off+2*aes.BlockSize <= len(kernel); off += 4 {
		if off&0xfff == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		block, err := aes.NewCipher(kernel[off : off+aes.BlockSize])
		if err != nil {
			return nil, err
		}
		iv := kernel[off+aes.BlockSize : off+2*aes.BlockSize]
		block.Encrypt(probe[:], iv)
		plausible := true
		for i, v := range xzMagic {
			if probe[i]^body[i] != v {
				plausible = false
				break
			}
		}
		if !plausible {
			continue
		}
		plain := make([]byte, len(body))
		cipher.NewCTR(block, iv).XORKeyStream(plain, body)
		hash := sha256.Sum256(plain)
		if !bytes.Equal(hash[:], digest) || !validStaticAESRootfs(ctx, plain, rootfsValidationMaxExpanded) {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("ambiguous static AES material: multiple candidates passed SHA-256 and XZ/CPIO validation")
		}
		match = &Result{Plaintext: plain, Cipher: "aes-128-ctr", HashOK: true,
			Seed:      &SeedMaterial{SeedOffset: off, BlobOffset: -1, Family: "aes-static"},
			KeyDetail: "static AES-128 key/IV (not displayed)"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return match, nil
}

func validStaticAESRootfs(ctx context.Context, plain []byte, maxExpanded int64) bool {
	if maxExpanded < 0 || maxExpanded == math.MaxInt64 {
		return false
	}
	r, err := xz.NewReader(bytes.NewReader(plain))
	if err != nil {
		return false
	}
	expanded := &io.LimitedReader{R: &contextReader{ctx: ctx, r: r}, N: maxExpanded + 1}
	return archive.ValidateNewc(expanded) == nil && expanded.N > 0 && ctx.Err() == nil
}
