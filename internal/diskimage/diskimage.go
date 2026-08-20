// Package diskimage is a minimal, read-only, pure-Go ext2/ext3 filesystem
// reader. It exists to replace `dd | debugfs -R rdump` in the firmware
// unpack pipeline: FortiOS firmware images are a 512-byte MBR sector
// followed by a plain ext3 "FORTIOS" volume (no extents, no 64bit feature,
// no metadata_csum, no journal replay needed since we never write). This
// package only needs to resolve a handful of files living directly in the
// root directory, so it implements just enough of ext2 to do that: the
// classic 32-byte block group descriptor, 128-byte inodes, and direct /
// single-indirect / double-indirect block mapping (triple-indirect is
// stubbed since none of our target files are large enough to need it).
package diskimage

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	superblockOffset = 1024
	superblockSize   = 1024
	ext2Magic        = 0xEF53

	bgDescSize = 32 // classic (non-64bit) block group descriptor

	defaultInodeSize = 128 // GOOD_OLD_REV inodes are always 128 bytes

	rootInode = 2

	s_IFMT  = 0xF000
	s_IFDIR = 0x4000
	s_IFREG = 0x8000

	dirEntryHeaderSize = 8

	nDirect       = 12
	iBlockSingle  = 12
	iBlockDouble  = 13
	iBlockTriple  = 14
	numIBlockPtrs = 15
)

type superblock struct {
	inodesCount    uint32
	blocksCount    uint32
	firstDataBlock uint32
	logBlockSize   uint32
	inodesPerGroup uint32
	blocksPerGroup uint32
	revLevel       uint32
	inodeSize      uint16
	blockSize      uint32
}

type groupDesc struct {
	inodeTableBlock uint32
}

// FS is a read-only handle on a parsed ext2/ext3 filesystem image.
type FS struct {
	data   []byte
	sb     superblock
	groups []groupDesc
}

// Open parses a raw ext2/ext3 partition image. data must NOT include the
// leading 512-byte MBR sector -- the caller strips that first. The
// superblock is located at byte offset 1024 within data.
func Open(data []byte) (*FS, error) {
	if len(data) < superblockOffset+superblockSize {
		return nil, fmt.Errorf("diskimage: image too small (%d bytes) to contain a superblock", len(data))
	}
	sbBytes := data[superblockOffset : superblockOffset+superblockSize]

	magic := binary.LittleEndian.Uint16(sbBytes[56:58])
	if magic != ext2Magic {
		return nil, fmt.Errorf("diskimage: bad superblock magic 0x%04X at offset %d, want 0x%04X", magic, superblockOffset+56, ext2Magic)
	}

	sb := superblock{
		inodesCount:    binary.LittleEndian.Uint32(sbBytes[0:4]),
		blocksCount:    binary.LittleEndian.Uint32(sbBytes[4:8]),
		firstDataBlock: binary.LittleEndian.Uint32(sbBytes[20:24]),
		logBlockSize:   binary.LittleEndian.Uint32(sbBytes[24:28]),
		blocksPerGroup: binary.LittleEndian.Uint32(sbBytes[32:36]),
		inodesPerGroup: binary.LittleEndian.Uint32(sbBytes[40:44]),
		revLevel:       binary.LittleEndian.Uint32(sbBytes[76:80]),
	}
	sb.blockSize = 1024 << sb.logBlockSize

	if sb.revLevel == 0 {
		sb.inodeSize = defaultInodeSize
	} else {
		sb.inodeSize = binary.LittleEndian.Uint16(sbBytes[88:90])
		if sb.inodeSize == 0 {
			sb.inodeSize = defaultInodeSize
		}
	}

	if sb.blocksPerGroup == 0 || sb.inodesPerGroup == 0 {
		return nil, fmt.Errorf("diskimage: superblock reports zero blocks/inodes per group")
	}

	fs := &FS{data: data, sb: sb}

	numGroups := (sb.blocksCount + sb.blocksPerGroup - 1) / sb.blocksPerGroup
	if numGroups == 0 {
		numGroups = 1
	}

	// Block group descriptor table starts in the block immediately
	// following the superblock's own block. For a 1024-byte block size
	// the superblock occupies block 1, so the table starts at block 2;
	// for larger block sizes the superblock lives inside block 0, so the
	// table starts at block 1.
	gdtBlock := uint64(sb.firstDataBlock) + 1
	gdtOffset := gdtBlock * uint64(sb.blockSize)
	gdtSize := uint64(numGroups) * bgDescSize
	if gdtOffset+gdtSize > uint64(len(data)) {
		return nil, fmt.Errorf("diskimage: block group descriptor table (offset %d, %d groups) runs past end of image (%d bytes)", gdtOffset, numGroups, len(data))
	}

	fs.groups = make([]groupDesc, numGroups)
	for i := uint32(0); i < numGroups; i++ {
		off := gdtOffset + uint64(i)*bgDescSize
		desc := data[off : off+bgDescSize]
		fs.groups[i] = groupDesc{
			inodeTableBlock: binary.LittleEndian.Uint32(desc[8:12]),
		}
	}

	return fs, nil
}

type inode struct {
	mode   uint16
	sizeLo uint32
	block  [numIBlockPtrs]uint32
}

func (f *FS) readInode(num uint32) (*inode, error) {
	if num == 0 {
		return nil, fmt.Errorf("diskimage: inode 0 is invalid")
	}
	group := (num - 1) / f.sb.inodesPerGroup
	index := (num - 1) % f.sb.inodesPerGroup
	if int(group) >= len(f.groups) {
		return nil, fmt.Errorf("diskimage: inode %d maps to group %d, only %d groups present", num, group, len(f.groups))
	}

	off := uint64(f.groups[group].inodeTableBlock)*uint64(f.sb.blockSize) + uint64(index)*uint64(f.sb.inodeSize)
	if off+128 > uint64(len(f.data)) {
		return nil, fmt.Errorf("diskimage: inode %d at offset %d runs past end of image", num, off)
	}
	raw := f.data[off : off+128]

	in := &inode{
		mode:   binary.LittleEndian.Uint16(raw[0:2]),
		sizeLo: binary.LittleEndian.Uint32(raw[4:8]),
	}
	for i := 0; i < numIBlockPtrs; i++ {
		in.block[i] = binary.LittleEndian.Uint32(raw[40+i*4 : 44+i*4])
	}
	return in, nil
}

func (f *FS) isDir(in *inode) bool { return in.mode&s_IFMT == s_IFDIR }
func (f *FS) isReg(in *inode) bool { return in.mode&s_IFMT == s_IFREG }

func (f *FS) readBlock(num uint32) []byte {
	buf := make([]byte, f.sb.blockSize)
	if num == 0 {
		return buf // sparse hole
	}
	off := uint64(num) * uint64(f.sb.blockSize)
	if off >= uint64(len(f.data)) {
		return buf
	}
	end := off + uint64(f.sb.blockSize)
	if end > uint64(len(f.data)) {
		end = uint64(len(f.data))
	}
	copy(buf, f.data[off:end])
	return buf
}

func (f *FS) blockPointers(blockNum uint32) []uint32 {
	raw := f.readBlock(blockNum)
	n := len(raw) / 4
	ptrs := make([]uint32, n)
	for i := 0; i < n; i++ {
		ptrs[i] = binary.LittleEndian.Uint32(raw[i*4 : i*4+4])
	}
	return ptrs
}

// readInodeData walks direct, single-indirect, and double-indirect block
// pointers to reassemble a file's full contents, then truncates to
// i_size_lo. Triple-indirect is not implemented: none of the files this
// package targets (flatkc ~4MB, rootfs.gz ~56MB, datafs.tar.gz ~14MB)
// require it -- double-indirect alone addresses (blockSize/4)^2 blocks,
// e.g. 256MB at a 4K block size.
func (f *FS) readInodeData(num uint32, in *inode) ([]byte, error) {
	blockSize := uint64(f.sb.blockSize)
	size := uint64(in.sizeLo)
	ptrsPerBlock := blockSize / 4
	// Bound work to exactly the blocks this file's size needs. Unused
	// slots in an indirect/double-indirect pointer table are not
	// guaranteed to be zeroed on these images -- walking the whole
	// (blockSize/4)^2 double-indirect address space unconditionally, as
	// an earlier version of this function did, could chase gigabytes of
	// garbage pointers past end-of-file before ever truncating to size.
	needed := (size + blockSize - 1) / blockSize

	out := make([]byte, 0, size+blockSize)
	var written uint64

	appendBlock := func(b uint32) {
		if written >= needed {
			return
		}
		out = append(out, f.readBlock(b)...)
		written++
	}
	appendHole := func(n uint64) {
		if written >= needed {
			return
		}
		remaining := needed - written
		if n > remaining {
			n = remaining
		}
		out = append(out, make([]byte, n*blockSize)...)
		written += n
	}

	for i := 0; i < nDirect && written < needed; i++ {
		appendBlock(in.block[i])
	}

	if written < needed {
		if in.block[iBlockSingle] != 0 {
			for _, b := range f.blockPointers(in.block[iBlockSingle]) {
				if written >= needed {
					break
				}
				appendBlock(b)
			}
		} else {
			appendHole(ptrsPerBlock)
		}
	}

	if written < needed {
		if in.block[iBlockDouble] != 0 {
			for _, indBlock := range f.blockPointers(in.block[iBlockDouble]) {
				if written >= needed {
					break
				}
				if indBlock == 0 {
					appendHole(ptrsPerBlock)
					continue
				}
				for _, b := range f.blockPointers(indBlock) {
					if written >= needed {
						break
					}
					appendBlock(b)
				}
			}
		} else {
			appendHole(ptrsPerBlock * ptrsPerBlock)
		}
	}

	if written < needed && in.block[iBlockTriple] != 0 {
		return nil, fmt.Errorf("diskimage: inode %d requires triple-indirect blocks, not supported", num)
	}

	if uint64(len(out)) < size {
		return nil, fmt.Errorf("diskimage: inode %d size %d exceeds mapped block data %d bytes (truncated file?)", num, size, len(out))
	}
	return out[:size], nil
}

// DirEntry describes one entry returned by ReadDir.
type DirEntry struct {
	Name  string
	IsDir bool
	Inode uint32
	Size  uint64
}

func (f *FS) readDirEntries(dirInodeNum uint32) ([]DirEntry, error) {
	in, err := f.readInode(dirInodeNum)
	if err != nil {
		return nil, fmt.Errorf("diskimage: reading directory inode %d: %w", dirInodeNum, err)
	}
	if !f.isDir(in) {
		return nil, fmt.Errorf("diskimage: inode %d is not a directory (mode 0x%04X)", dirInodeNum, in.mode)
	}

	data, err := f.readInodeData(dirInodeNum, in)
	if err != nil {
		return nil, fmt.Errorf("diskimage: reading directory data for inode %d: %w", dirInodeNum, err)
	}

	var entries []DirEntry
	blockSize := int(f.sb.blockSize)
	for blockStart := 0; blockStart+dirEntryHeaderSize <= len(data); blockStart += blockSize {
		blockEnd := blockStart + blockSize
		if blockEnd > len(data) {
			blockEnd = len(data)
		}
		off := blockStart
		for off+dirEntryHeaderSize <= blockEnd {
			entInode := binary.LittleEndian.Uint32(data[off : off+4])
			recLen := binary.LittleEndian.Uint16(data[off+4 : off+6])
			nameLen := data[off+6]
			fileType := data[off+7]
			if recLen == 0 {
				break
			}
			nameEnd := off + dirEntryHeaderSize + int(nameLen)
			if nameEnd > blockEnd {
				return nil, fmt.Errorf("diskimage: directory inode %d has corrupt entry at offset %d (name overruns block)", dirInodeNum, off)
			}
			if entInode != 0 {
				name := string(data[off+dirEntryHeaderSize : nameEnd])
				if name != "." && name != ".." {
					isDir := fileType == 2
					var size uint64
					if !isDir {
						childInode, err := f.readInode(entInode)
						if err == nil {
							if fileType == 0 {
								isDir = f.isDir(childInode)
							}
							if !isDir {
								size = uint64(childInode.sizeLo)
							}
						}
					}
					entries = append(entries, DirEntry{
						Name:  name,
						IsDir: isDir,
						Inode: entInode,
						Size:  size,
					})
				}
			}
			off += int(recLen)
		}
	}
	return entries, nil
}

func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

// resolve walks path components from the root inode, returning the inode
// number of the final component.
func (f *FS) resolve(path string) (uint32, error) {
	parts := splitPath(path)
	cur := uint32(rootInode)
	walked := ""
	for _, part := range parts {
		entries, err := f.readDirEntries(cur)
		if err != nil {
			return 0, fmt.Errorf("diskimage: resolving %q: %w", path, err)
		}
		found := false
		for _, e := range entries {
			if e.Name == part {
				cur = e.Inode
				found = true
				break
			}
		}
		if !found {
			if walked == "" {
				walked = "/"
			}
			return 0, fmt.Errorf("diskimage: %q not found under %q (resolving %q)", part, walked, path)
		}
		walked = walked + "/" + part
	}
	return cur, nil
}

// ReadFile reads a regular file by root-relative path, e.g. "flatkc" or
// "lib/libips.so.new.x". A leading slash is tolerated but not required.
func (f *FS) ReadFile(path string) ([]byte, error) {
	num, err := f.resolve(path)
	if err != nil {
		return nil, err
	}
	in, err := f.readInode(num)
	if err != nil {
		return nil, fmt.Errorf("diskimage: reading file %q (inode %d): %w", path, num, err)
	}
	if !f.isReg(in) {
		return nil, fmt.Errorf("diskimage: %q (inode %d) is not a regular file (mode 0x%04X)", path, num, in.mode)
	}
	data, err := f.readInodeData(num, in)
	if err != nil {
		return nil, fmt.Errorf("diskimage: reading file %q (inode %d): %w", path, num, err)
	}
	return data, nil
}

// ReadDir lists the immediate entries of a directory. "" or "/" means root.
func (f *FS) ReadDir(path string) ([]DirEntry, error) {
	num := uint32(rootInode)
	if strings.Trim(path, "/") != "" {
		var err error
		num, err = f.resolve(path)
		if err != nil {
			return nil, err
		}
		in, err := f.readInode(num)
		if err != nil {
			return nil, fmt.Errorf("diskimage: reading dir %q (inode %d): %w", path, num, err)
		}
		if !f.isDir(in) {
			return nil, fmt.Errorf("diskimage: %q (inode %d) is not a directory (mode 0x%04X)", path, num, in.mode)
		}
	}
	return f.readDirEntries(num)
}
