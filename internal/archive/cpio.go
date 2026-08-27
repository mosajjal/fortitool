package archive

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	newcMagic        = "070701"
	newcCRCMagic     = "070702"
	newcHeaderSize   = 110
	maxCPIONameSize  = 1 << 20
	maxCPIOLinkSize  = 1 << 20
	maxCPIOPathDepth = 1024
	cpioTrailer      = "TRAILER!!!"
	cpioModeTypeMask = 0o170000
	cpioModeSocket   = 0o140000
	cpioModeSymlink  = 0o120000
	cpioModeRegular  = 0o100000
	cpioModeBlock    = 0o060000
	cpioModeDir      = 0o040000
	cpioModeChar     = 0o020000
	cpioModeFIFO     = 0o010000
)

type newcHeader struct {
	ino      uint64
	mode     uint64
	nlink    uint64
	fileSize uint64
	devMajor uint64
	devMinor uint64
	nameSize uint64
	check    uint64
}

type cpioHardLinkKey struct {
	devMajor uint64
	devMinor uint64
	ino      uint64
}

type cpioPendingLink struct {
	path string
	mode os.FileMode
}

type cpioHardLinkGroup struct {
	key      cpioHardLinkKey
	nlink    uint64
	mode     os.FileMode
	count    uint64
	dataPath string
	pending  []cpioPendingLink
}

type cpioPathNode struct {
	kind     string
	children map[string]*cpioPathNode
}

// ExtractNewc extracts a single ASCII newc CPIO archive. The CRC variant is
// deliberately rejected until checksum semantics are implemented.
func ExtractNewc(r io.Reader, destDir string) error {
	root, err := openArchiveRoot(destDir)
	if err != nil {
		return err
	}
	defer root.Close()

	paths := &cpioPathNode{}
	groups := make(map[cpioHardLinkKey]*cpioHardLinkGroup)
	var groupOrder []cpioHardLinkKey

	for {
		hdr, err := readNewcHeader(r)
		if errors.Is(err, io.EOF) {
			return errors.New("cpio: missing TRAILER!!! entry")
		}
		if err != nil {
			return err
		}
		name, err := readNewcName(r, hdr.nameSize)
		if err != nil {
			return err
		}
		if err := readNewcPadding(r, newcHeaderSize+hdr.nameSize, "name"); err != nil {
			return err
		}
		if name == cpioTrailer {
			if hdr.fileSize != 0 {
				return errors.New("cpio: TRAILER!!! entry has non-zero size")
			}
			if err := readNewcTrailerPadding(r); err != nil {
				return err
			}
			if err := resolveCPIOHardLinks(root, groups, groupOrder); err != nil {
				return err
			}
			return nil
		}
		target, err := safeCPIOPath(name)
		if err != nil {
			return err
		}
		if err := recordCPIOPath(paths, target, cpioTypeName(hdr.mode), name); err != nil {
			return err
		}

		switch hdr.mode & cpioModeTypeMask {
		case cpioModeDir:
			if hdr.fileSize != 0 {
				return fmt.Errorf("cpio directory %q has non-zero size", name)
			}
			if err := createCPIODirectory(root, target); err != nil {
				return err
			}
		case cpioModeRegular:
			if hdr.nlink == 0 {
				return fmt.Errorf("cpio file %q has zero link count", name)
			}
			mode := os.FileMode(hdr.mode)&0o777 | 0o200
			if hdr.nlink == 1 {
				if err := writeCPIORegular(root, r, target, mode, hdr.fileSize); err != nil {
					return err
				}
			} else {
				key := cpioHardLinkKey{devMajor: hdr.devMajor, devMinor: hdr.devMinor, ino: hdr.ino}
				group := groups[key]
				if group == nil {
					group = &cpioHardLinkGroup{key: key, nlink: hdr.nlink, mode: mode}
					groups[key] = group
					groupOrder = append(groupOrder, key)
				}
				if group.nlink != hdr.nlink || group.mode != mode {
					return fmt.Errorf("cpio hard-link group for %q has inconsistent metadata", name)
				}
				group.count++
				if group.count > group.nlink {
					return fmt.Errorf("cpio hard-link group for %q exceeds declared link count", name)
				}
				if hdr.fileSize != 0 {
					if group.dataPath != "" {
						return fmt.Errorf("cpio hard-link group for %q has multiple data members", name)
					}
					if err := writeCPIORegular(root, r, target, mode, hdr.fileSize); err != nil {
						return err
					}
					group.dataPath = target
				} else {
					if err := prepareCPIOOutput(root, target); err != nil {
						return err
					}
					group.pending = append(group.pending, cpioPendingLink{path: target, mode: mode})
				}
			}
		case cpioModeSymlink:
			if hdr.nlink == 0 {
				return fmt.Errorf("cpio symlink %q has zero link count", name)
			}
			if hdr.fileSize == 0 || hdr.fileSize > maxCPIOLinkSize {
				return fmt.Errorf("cpio symlink %q has invalid target size %d", name, hdr.fileSize)
			}
			linkBytes := make([]byte, int(hdr.fileSize))
			if _, err := io.ReadFull(r, linkBytes); err != nil {
				return fmt.Errorf("cpio symlink %q is truncated: %w", name, err)
			}
			if err := readNewcPadding(r, hdr.fileSize, "file data"); err != nil {
				return err
			}
			linkTarget, err := safeSymlinkTarget("cpio", target, string(linkBytes))
			if err != nil {
				return err
			}
			if err := prepareCPIOOutput(root, target); err != nil {
				return err
			}
			if err := root.Symlink(linkTarget, target); err != nil {
				return err
			}
		case cpioModeBlock, cpioModeChar, cpioModeFIFO, cpioModeSocket:
			if hdr.fileSize != 0 {
				return fmt.Errorf("cpio special node %q has non-zero size", name)
			}
		default:
			return fmt.Errorf("cpio entry %q has unsupported file type (%#o)", name, hdr.mode&cpioModeTypeMask)
		}

		if hdr.mode&cpioModeTypeMask != cpioModeRegular || hdr.fileSize == 0 {
			if hdr.mode&cpioModeTypeMask != cpioModeSymlink {
				if hdr.fileSize != 0 {
					return fmt.Errorf("cpio entry %q has unexpected data", name)
				}
				if err := readNewcPadding(r, hdr.fileSize, "file data"); err != nil {
					return err
				}
			}
		}
	}
}

func readNewcHeader(r io.Reader) (*newcHeader, error) {
	raw := make([]byte, newcHeaderSize)
	n, err := io.ReadFull(r, raw)
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("cpio: truncated header: %w", err)
	}
	magic := string(raw[:6])
	if magic == newcCRCMagic {
		return nil, errors.New("cpio: CRC-form 070702 is not supported")
	}
	if magic != newcMagic {
		return nil, fmt.Errorf("cpio: unsupported magic %q", magic)
	}

	values := make([]uint64, 13)
	for i := range values {
		field := raw[6+i*8 : 14+i*8]
		if _, err := hex.Decode(make([]byte, 4), field); err != nil {
			return nil, fmt.Errorf("cpio: malformed hexadecimal field %d: %w", i, err)
		}
		value, err := strconv.ParseUint(string(field), 16, 32)
		if err != nil {
			return nil, fmt.Errorf("cpio: malformed hexadecimal field %d: %w", i, err)
		}
		values[i] = value
	}
	hdr := &newcHeader{
		ino: values[0], mode: values[1], nlink: values[4],
		fileSize: values[6], devMajor: values[7], devMinor: values[8],
		nameSize: values[11], check: values[12],
	}
	if hdr.check != 0 {
		return nil, fmt.Errorf("cpio: newc check field is non-zero (%#x)", hdr.check)
	}
	if hdr.nameSize == 0 || hdr.nameSize > maxCPIONameSize || hdr.nameSize > math.MaxInt {
		return nil, fmt.Errorf("cpio: unreasonable name size %d", hdr.nameSize)
	}
	return hdr, nil
}

func readNewcName(r io.Reader, size uint64) (string, error) {
	raw := make([]byte, int(size))
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", fmt.Errorf("cpio: truncated name: %w", err)
	}
	if raw[len(raw)-1] != 0 {
		return "", errors.New("cpio: name is not NUL-terminated")
	}
	if strings.IndexByte(string(raw[:len(raw)-1]), 0) >= 0 {
		return "", errors.New("cpio: name contains an embedded NUL byte")
	}
	return string(raw[:len(raw)-1]), nil
}

func readNewcPadding(r io.Reader, size uint64, field string) error {
	padding := (4 - (size & 3)) & 3
	if padding == 0 {
		return nil
	}
	var raw [3]byte
	if _, err := io.ReadFull(r, raw[:padding]); err != nil {
		return fmt.Errorf("cpio: truncated %s padding: %w", field, err)
	}
	for _, b := range raw[:padding] {
		if b != 0 {
			return fmt.Errorf("cpio: non-zero %s padding", field)
		}
	}
	return nil
}

func readNewcTrailerPadding(r io.Reader) error {
	var raw [4096]byte
	for {
		n, err := r.Read(raw[:])
		for _, b := range raw[:n] {
			if b != 0 {
				return errors.New("cpio: non-zero data after TRAILER!!! entry")
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("cpio: trailing padding: %w", err)
		}
	}
}

func safeCPIOPath(name string) (string, error) {
	if name == "" {
		return "", errors.New("cpio entry has an empty name")
	}
	slashName := strings.ReplaceAll(name, `\`, "/")
	if path.IsAbs(slashName) || filepath.IsAbs(name) {
		return "", fmt.Errorf("cpio entry uses an absolute path: %q", name)
	}
	target, err := safeArchivePath("cpio", name)
	if err != nil {
		return "", err
	}
	if target != "." && strings.Count(filepath.ToSlash(target), "/") >= maxCPIOPathDepth {
		return "", fmt.Errorf("cpio entry has more than %d path components: %q", maxCPIOPathDepth, name)
	}
	return target, nil
}

func createCPIODirectory(root *os.Root, target string) error {
	if target == "." {
		return nil
	}
	if err := mkdirArchiveDir(root, filepath.Dir(target)); err != nil {
		return err
	}
	if _, err := root.Lstat(target); err == nil {
		return fmt.Errorf("cpio directory collides with existing output: %q", target)
	} else if !os.IsNotExist(err) {
		return err
	}
	return root.Mkdir(target, 0o755)
}

func cpioTypeName(mode uint64) string {
	switch mode & cpioModeTypeMask {
	case cpioModeDir:
		return "directory"
	case cpioModeRegular:
		return "file"
	case cpioModeSymlink:
		return "symlink"
	default:
		return "special"
	}
}

func recordCPIOPath(root *cpioPathNode, target, kind, name string) error {
	if target == "." {
		if kind != "directory" {
			return fmt.Errorf("cpio %s entry resolves to archive root: %q", kind, name)
		}
		if root.kind != "" {
			return fmt.Errorf("cpio entry collides with prior %s output: %q", root.kind, name)
		}
		root.kind = kind
		return nil
	}

	node := root
	components := strings.Split(filepath.ToSlash(target), "/")
	for i, component := range components {
		if node.kind != "" && node.kind != "directory" {
			parent := filepath.FromSlash(strings.Join(components[:i], "/"))
			return fmt.Errorf("cpio entry descends through prior %s output %q: %q", node.kind, parent, name)
		}
		if node.children == nil {
			node.children = make(map[string]*cpioPathNode)
		}
		child := node.children[component]
		if child == nil {
			child = &cpioPathNode{}
			node.children[component] = child
		}
		node = child
	}
	if node.kind != "" {
		return fmt.Errorf("cpio entry collides with prior %s output: %q", node.kind, name)
	}
	if len(node.children) != 0 {
		return fmt.Errorf("cpio entry collides with a prior implicit directory: %q", name)
	}
	node.kind = kind
	return nil
}

func prepareCPIOOutput(root *os.Root, target string) error {
	if target == "." {
		return errors.New("cpio non-directory entry resolves to archive root")
	}
	if err := mkdirArchiveDir(root, filepath.Dir(target)); err != nil {
		return err
	}
	if _, err := root.Lstat(target); err == nil {
		return fmt.Errorf("cpio entry collides with existing output: %q", target)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func writeCPIORegular(root *os.Root, r io.Reader, target string, mode os.FileMode, size uint64) error {
	if size > math.MaxInt64 {
		return fmt.Errorf("cpio file %q has unreasonable size %d", target, size)
	}
	if err := prepareCPIOOutput(root, target); err != nil {
		return err
	}
	f, err := root.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(f, r, int64(size)); err != nil {
		_ = f.Close()
		_ = root.Remove(target)
		return fmt.Errorf("cpio file %q is truncated: %w", target, err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(target)
		return err
	}
	if err := readNewcPadding(r, size, "file data"); err != nil {
		_ = root.Remove(target)
		return err
	}
	return nil
}

func resolveCPIOHardLinks(root *os.Root, groups map[cpioHardLinkKey]*cpioHardLinkGroup, order []cpioHardLinkKey) error {
	for _, key := range order {
		group := groups[key]
		if group.count != group.nlink {
			return fmt.Errorf("cpio hard-link group inode %d has %d of %d declared members", group.key.ino, group.count, group.nlink)
		}
		if group.dataPath == "" {
			if len(group.pending) < 2 {
				return fmt.Errorf("cpio hard-link group inode %d has no data-bearing or complete empty target", group.key.ino)
			}
			first := group.pending[0]
			if err := writeCPIORegular(root, strings.NewReader(""), first.path, first.mode, 0); err != nil {
				return err
			}
			group.dataPath = first.path
			group.pending = group.pending[1:]
		}
		if err := checkArchiveDir(root, filepath.Dir(group.dataPath)); err != nil {
			return fmt.Errorf("cpio hard-link target %q: %w", group.dataPath, err)
		}
		info, err := root.Lstat(group.dataPath)
		if err != nil {
			return fmt.Errorf("cpio hard-link target %q: %w", group.dataPath, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("cpio hard-link target is not a regular file: %q", group.dataPath)
		}
		for _, pending := range group.pending {
			if err := prepareCPIOOutput(root, pending.path); err != nil {
				return err
			}
			if err := root.Link(group.dataPath, pending.path); err != nil {
				return err
			}
		}
	}
	return nil
}
