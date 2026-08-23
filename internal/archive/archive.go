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
	"path"
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
	// FortiOS may append signature or installer data after a valid first
	// member. Validate that member fully without treating the tail as another
	// gzip stream.
	gz.Multistream(false)
	if err := Untar(gz, destDir); err != nil {
		return err
	}
	// archive/tar stops after the two end-of-archive records. Drain the gzip
	// reader so its checksum and size trailer are still validated rather than
	// accepting a truncated member after publishing a seemingly complete tar.
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	return nil
}

// ExtractXZTar decompresses xz-compressed tar data (bin.tar.xz, usr.tar.xz,
// migadmin.tar.xz, node-scripts.tar.xz) and writes it under destDir.
func ExtractXZTar(data []byte, destDir string) error {
	xr, err := xz.NewReader(newByteReader(data))
	if err != nil {
		return fmt.Errorf("xz: %w", err)
	}
	if err := Untar(xr, destDir); err != nil {
		return err
	}
	// archive/tar stops after the two end-of-archive records. Drain the XZ
	// reader so the remaining block/check/index/footer data is validated.
	if _, err := io.Copy(io.Discard, xr); err != nil {
		return fmt.Errorf("xz: %w", err)
	}
	return nil
}

// XZDecompress fully decompresses a raw xz stream (not a tar).
func XZDecompress(data []byte) ([]byte, error) {
	xr, err := xz.NewReader(newByteReader(data))
	if err != nil {
		return nil, fmt.Errorf("xz: %w", err)
	}
	plain, err := io.ReadAll(xr)
	if err != nil {
		return nil, fmt.Errorf("xz: %w", err)
	}
	return plain, nil
}

// Untar extracts a tar stream to destDir, handling regular files,
// directories, and symlinks (FortiOS rootfs trees use symlinks heavily,
// e.g. /etc -> data/etc).
func Untar(r io.Reader, destDir string) error {
	info, err := os.Lstat(destDir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(destDir, 0o755); err != nil {
			return err
		}
		info, err = os.Lstat(destDir)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("archive extraction destination is not a real directory: %q", destDir)
	}
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return err
	}
	defer root.Close()

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		target, err := safeArchivePath(hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirArchiveDir(root, target); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA, tar.TypeGNUSparse:
			if err := mkdirArchiveDir(root, filepath.Dir(target)); err != nil {
				return err
			}
			if _, err := root.Lstat(target); err == nil {
				return fmt.Errorf("tar entry collides with existing output: %q", hdr.Name)
			} else if !os.IsNotExist(err) {
				return err
			}
			f, err := root.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777|0o200)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				_ = root.Remove(target)
				return err
			}
			if err := f.Close(); err != nil {
				_ = root.Remove(target)
				return err
			}
		case tar.TypeSymlink:
			if err := mkdirArchiveDir(root, filepath.Dir(target)); err != nil {
				return err
			}
			if _, err := root.Lstat(target); err == nil {
				return fmt.Errorf("tar entry collides with existing output: %q", hdr.Name)
			} else if !os.IsNotExist(err) {
				return err
			}
			linkTarget, err := safeSymlinkTarget(target, hdr.Linkname)
			if err != nil {
				return err
			}
			if err := root.Symlink(linkTarget, target); err != nil {
				return err
			}
		case tar.TypeLink:
			linkTarget, err := safeArchivePath(hdr.Linkname)
			if err != nil {
				return err
			}
			if err := mkdirArchiveDir(root, filepath.Dir(target)); err != nil {
				return err
			}
			if err := checkArchiveDir(root, filepath.Dir(linkTarget)); err != nil {
				return fmt.Errorf("tar hard-link target %q: %w", hdr.Linkname, err)
			}
			info, err := root.Lstat(linkTarget)
			if err != nil {
				return fmt.Errorf("tar hard-link target %q: %w", hdr.Linkname, err)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("tar hard-link target is not a regular file: %q", hdr.Linkname)
			}
			if _, err := root.Lstat(target); err == nil {
				return fmt.Errorf("tar entry collides with existing output: %q", hdr.Name)
			} else if !os.IsNotExist(err) {
				return err
			}
			if err := root.Link(linkTarget, target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported tar entry type %q for %q", hdr.Typeflag, hdr.Name)
		}
	}
}

func safeArchivePath(name string) (string, error) {
	if strings.ContainsRune(name, '\x00') {
		return "", fmt.Errorf("tar entry contains a NUL byte: %q", name)
	}
	// Tar paths use slash separators. Treat backslashes as separators too so
	// an archive has the same safety result on Unix and Windows.
	slashName := strings.ReplaceAll(name, `\`, "/")
	for part := range strings.SplitSeq(slashName, "/") {
		if part == ".." {
			return "", fmt.Errorf("tar entry contains a path traversal component: %q", name)
		}
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+slashName), "/")
	if cleaned == "" || cleaned == "." {
		return ".", nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("tar entry escapes destination: %q", name)
	}
	return filepath.FromSlash(cleaned), nil
}

func mkdirArchiveDir(root *os.Root, name string) error {
	return walkArchiveDir(root, name, true)
}

func checkArchiveDir(root *os.Root, name string) error {
	return walkArchiveDir(root, name, false)
}

// walkArchiveDir checks every path component rather than only the final
// directory. This prevents writes and hard-link lookups from traversing a
// symlink that either existed before extraction or was created by an earlier
// archive entry.
func walkArchiveDir(root *os.Root, name string, create bool) error {
	if name == "" || name == "." {
		return nil
	}
	current := ""
	for _, component := range strings.Split(filepath.ToSlash(filepath.Clean(name)), "/") {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, filepath.FromSlash(component))
		info, err := root.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("archive path traverses a symlink: %q", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("archive directory collides with non-directory: %q", current)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return err
		}
		if !create {
			return fmt.Errorf("archive directory does not exist: %q", current)
		}
		if err := root.Mkdir(current, 0o755); err != nil {
			return fmt.Errorf("creating archive directory %q: %w", current, err)
		}
	}
	return nil
}

func safeSymlinkTarget(linkName, linkTarget string) (string, error) {
	if linkTarget == "" || strings.ContainsRune(linkTarget, '\x00') {
		return "", fmt.Errorf("tar symlink %q has an invalid target", linkName)
	}
	target := strings.ReplaceAll(linkTarget, `\`, "/")
	if path.IsAbs(target) {
		target = strings.TrimPrefix(path.Clean(target), "/")
	} else {
		target = path.Clean(path.Join(path.Dir(filepath.ToSlash(linkName)), target))
	}
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", fmt.Errorf("tar symlink %q escapes destination: %q", linkName, linkTarget)
	}
	relative, err := filepath.Rel(filepath.Dir(linkName), filepath.FromSlash(target))
	if err != nil {
		return "", err
	}
	return relative, nil
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
