// Package archive unpacks the two archive layers found inside a decrypted
// FortiOS rootfs.gz: the outer container is a plain GNU tar (despite
// upstream write-ups calling it "cpio" -- verified empirically against real
// FWF-60E images, see testdata), and several members inside it
// (bin.tar.xz, usr.tar.xz, migadmin.tar.xz, node-scripts.tar.xz) are
// tar+xz. Both layers are handled with Go's standard library plus a pure-Go
// xz decoder -- no `tar`, `cpio`, or `xz` binaries required.
package archive

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

// ExtractGzipTar decompresses gzip-compressed tar data and writes it under
// destDir. This is what a decrypted rootfs.gz becomes after AES-CTR/RC4
// decryption.
func ExtractGzipTar(data []byte, destDir string) error {
	gz, err := gzip.NewReader(newByteReader(data))
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	return Untar(gz, destDir)
}

// ExtractXZTar decompresses xz-compressed tar data (bin.tar.xz, usr.tar.xz,
// migadmin.tar.xz, node-scripts.tar.xz) and writes it under destDir.
func ExtractXZTar(data []byte, destDir string) error {
	xr, err := xz.NewReader(newByteReader(data))
	if err != nil {
		return fmt.Errorf("xz: %w", err)
	}
	return Untar(xr, destDir)
}

// XZDecompress fully decompresses a raw xz stream (not a tar). This is
// what a FortiOS 8.0 VM rootfs body becomes after decryption: an
// xz-compressed ext4 filesystem image rather than a gzipped tar.
func XZDecompress(data []byte) ([]byte, error) {
	xr, err := xz.NewReader(newByteReader(data))
	if err != nil {
		return nil, fmt.Errorf("xz: %w", err)
	}
	return io.ReadAll(xr)
}

// Untar extracts a tar stream to destDir, handling regular files,
// directories, and symlinks (FortiOS rootfs trees use symlinks heavily,
// e.g. /etc -> data/etc).
func Untar(r io.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		target, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777|0o200)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			// hard link: best-effort, ignore missing target (order-dependent)
			linkTarget, err := safeJoin(destDir, hdr.Linkname)
			if err == nil {
				_ = os.Link(linkTarget, target)
			}
		default:
			// devices, fifos etc: skip, not needed for static analysis
		}
	}
}

func safeJoin(destDir, name string) (string, error) {
	for part := range strings.SplitSeq(filepath.ToSlash(name), "/") {
		if part == ".." {
			return "", fmt.Errorf("tar entry contains a path traversal component: %q", name)
		}
	}
	cleaned := filepath.Clean("/" + name)
	target := filepath.Join(destDir, cleaned)
	if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) && target != filepath.Clean(destDir) {
		return "", fmt.Errorf("tar entry escapes destination: %q", name)
	}
	return target, nil
}

type byteReader struct {
	data []byte
	pos  int
}

func newByteReader(data []byte) *byteReader { return &byteReader{data: data} }

func (b *byteReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}
