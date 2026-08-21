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
	"io"
	"os"
	"path/filepath"
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
	s_IFLNK = 0xA000

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

// source abstracts where filesystem bytes come from: either an in-memory
// slice (classic appliance images) or an arbitrary io.ReaderAt (e.g. a
// qcow2 VM disk, which must not be materialized in RAM whole).
type source interface {
	size() int64
	at(p []byte, off int64) error // fills p completely or errors
}

type sliceSource struct{ data []byte }

func (s sliceSource) size() int64 { return int64(len(s.data)) }
func (s sliceSource) at(p []byte, off int64) error {
	if off < 0 || off+int64(len(p)) > int64(len(s.data)) {
		return fmt.Errorf("diskimage: read at %d (%d bytes) past end of image (%d bytes)", off, len(p), len(s.data))
	}
	copy(p, s.data[off:off+int64(len(p))])
	return nil
}

type readerSource struct {
	r  io.ReaderAt
	sz int64
}

func (s readerSource) size() int64 { return s.sz }
func (s readerSource) at(p []byte, off int64) error {
	if _, err := s.r.ReadAt(p, off); err != nil {
		return fmt.Errorf("diskimage: read at %d (%d bytes): %w", off, len(p), err)
	}
	return nil
}

// FS is a read-only handle on a parsed ext2/ext3/ext4 filesystem image.
type FS struct {
	src    source
	sb     superblock
	groups []groupDesc
}

// Open parses a raw ext2/ext3 partition image held in memory. data must
// NOT include the leading 512-byte MBR sector -- the caller strips that
// first. The superblock is located at byte offset 1024 within data.
func Open(data []byte) (*FS, error) {
	return open(sliceSource{data: data})
}

// OpenAt parses an ext2/3/4 filesystem that starts at byte 0 of r (r may
// itself be windowed to a partition start by the caller). size is the
// number of readable bytes from position 0.
func OpenAt(r io.ReaderAt, size int64) (*FS, error) {
	return open(readerSource{r: r, sz: size})
}

func open(src source) (*FS, error) {
	if src.size() < superblockOffset+superblockSize {
		return nil, fmt.Errorf("diskimage: image too small (%d bytes) to contain a superblock", src.size())
	}
	sbBytes := make([]byte, superblockSize)
	if err := src.at(sbBytes, superblockOffset); err != nil {
		return nil, fmt.Errorf("diskimage: reading superblock: %w", err)
	}

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

	fs := &FS{src: src, sb: sb}

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
	if gdtOffset+gdtSize > uint64(src.size()) {
		return nil, fmt.Errorf("diskimage: block group descriptor table (offset %d, %d groups) runs past end of image (%d bytes)", gdtOffset, numGroups, src.size())
	}

	fs.groups = make([]groupDesc, numGroups)
	for i := uint32(0); i < numGroups; i++ {
		off := gdtOffset + uint64(i)*bgDescSize
		desc := make([]byte, bgDescSize)
		if err := src.at(desc, int64(off)); err != nil {
			return nil, fmt.Errorf("diskimage: reading group descriptor %d: %w", i, err)
		}
		fs.groups[i] = groupDesc{
			inodeTableBlock: binary.LittleEndian.Uint32(desc[8:12]),
		}
	}

	return fs, nil
}

type inode struct {
	mode     uint16
	sizeLo   uint32
	block    [numIBlockPtrs]uint32
	blockRaw [60]byte // raw i_block bytes, needed for extent-tree parsing
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
	if off+128 > uint64(f.src.size()) {
		return nil, fmt.Errorf("diskimage: inode %d at offset %d runs past end of image", num, off)
	}
	raw := make([]byte, 128)
	if err := f.src.at(raw, int64(off)); err != nil {
		return nil, fmt.Errorf("diskimage: reading inode %d: %w", num, err)
	}

	in := &inode{
		mode:   binary.LittleEndian.Uint16(raw[0:2]),
		sizeLo: binary.LittleEndian.Uint32(raw[4:8]),
	}
	for i := 0; i < numIBlockPtrs; i++ {
		in.block[i] = binary.LittleEndian.Uint32(raw[40+i*4 : 44+i*4])
	}
	copy(in.blockRaw[:], raw[40:100])
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
	if off >= uint64(f.src.size()) {
		return buf
	}
	if err := f.src.at(buf, int64(off)); err != nil {
		return buf // treat unreadable tail as a hole; callers bound by file size
	}
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

// extentMagic is the ext4 extent-tree header magic (0xF30A, little-endian
// in the first two bytes of i_block). Its presence reliably distinguishes
// extent-mapped inodes from classic indirect-pointer maps.
const extentMagic = 0xF30A

// readInodeData dispatches between the two on-disk block-mapping schemes:
// ext2/3-style direct+indirect pointers and ext4-style extent trees (used
// by newer images such as FortiOS 8.0's ext4 rootfs).
func (f *FS) readInodeData(num uint32, in *inode) ([]byte, error) {
	if le := binary.LittleEndian.Uint16(in.blockRaw[0:2]); le == extentMagic {
		return f.readInodeDataExtents(num, in)
	}
	return f.readInodeDataIndirect(num, in)
}

// extent is one flattened leaf entry of an extent tree.
type extent struct {
	logical  uint32 // first logical block
	physical uint32 // first physical block (0 = hole when len==0)
	count    uint32 // number of blocks
	uninit   bool
}

// collectExtents walks the extent tree rooted at root (the raw i_block
// bytes) and returns its leaf extents in logical order.
func (f *FS) collectExtents(root []byte) ([]extent, error) {
	var leaves []extent

	// extent header: eh_magic(2) eh_entries(2) eh_max(2) eh_depth(2)
	// eh_generation(4); leaf/index entries of 12 bytes follow
	headerSize := 12
	entries := int(binary.LittleEndian.Uint16(root[2:4]))
	depth := binary.LittleEndian.Uint16(root[6:8])
	if entries < 0 || headerSize+entries*12 > len(root) {
		return nil, fmt.Errorf("diskimage: corrupt extent header (%d entries)", entries)
	}

	if depth == 0 {
		for i := 0; i < entries; i++ {
			e := root[headerSize+i*12 : headerSize+(i+1)*12]
			eeLen := binary.LittleEndian.Uint16(e[4:6])
			uninit := eeLen > 32768
			if uninit {
				eeLen -= 32768
			}
			leaves = append(leaves, extent{
				logical:  binary.LittleEndian.Uint32(e[0:4]),
				physical: uint64ToBlock(binary.LittleEndian.Uint16(e[6:8]), binary.LittleEndian.Uint32(e[8:12])),
				count:    uint32(eeLen),
				uninit:   uninit,
			})
		}
		return leaves, nil
	}

	for i := 0; i < entries; i++ {
		idx := root[headerSize+i*12 : headerSize+(i+1)*12]
		// index entry: ei_block(4) ei_leaf_lo(4) ei_leaf_hi(2) unused(2)
		leafBlock := uint64ToBlock(binary.LittleEndian.Uint16(idx[8:10]), binary.LittleEndian.Uint32(idx[4:8]))
		node := make([]byte, f.sb.blockSize)
		if leafBlock != 0 {
			if err := f.src.at(node, int64(uint64(leafBlock)*uint64(f.sb.blockSize))); err != nil {
				return nil, fmt.Errorf("diskimage: reading extent index node at block %d: %w", leafBlock, err)
			}
		}
		sub, err := f.collectExtents(node)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, sub...)
	}
	return leaves, nil
}

func uint64ToBlock(hi uint16, lo uint32) uint32 {
	// filesystems we target are < 16 TiB; high bits beyond uint32 would
	// indicate a 64-bit feature image this reader does not support
	if hi != 0 {
		return 0xFFFFFFFF
	}
	return lo
}

func (f *FS) readInodeDataExtents(num uint32, in *inode) ([]byte, error) {
	blockSize := uint64(f.sb.blockSize)
	size := uint64(in.sizeLo)
	needed := (size + blockSize - 1) / blockSize

	extents, err := f.collectExtents(in.blockRaw[:])
	if err != nil {
		return nil, fmt.Errorf("diskimage: inode %d: %w", num, err)
	}

	out := make([]byte, 0, size+blockSize)
	var written uint64
	nextLogical := uint64(0)

	emitHole := func(n uint64) {
		for i := uint64(0); i < n && written < needed; i++ {
			out = append(out, make([]byte, blockSize)...)
			written++
		}
	}

	for _, e := range extents {
		if written >= needed {
			break
		}
		logical := uint64(e.logical)
		if logical > nextLogical {
			emitHole(logical - nextLogical)
			nextLogical = logical
			if written >= needed {
				break
			}
		}
		if logical+uint64(e.count) <= nextLogical {
			continue // extent entirely before the remaining window
		}
		for i := uint32(nextLogical - logical); i < e.count && written < needed; i++ {
			if e.uninit || e.physical == 0 {
				out = append(out, make([]byte, blockSize)...)
			} else {
				out = append(out, f.readBlock(e.physical+i)...)
			}
			written++
		}
		nextLogical = logical + uint64(e.count)
	}
	if written < needed {
		emitHole(needed - written)
	}

	if uint64(len(out)) < size {
		return nil, fmt.Errorf("diskimage: inode %d size %d exceeds mapped block data %d bytes (truncated file?)", num, size, len(out))
	}
	return out[:size], nil
}

// readInodeDataIndirect walks direct, single-indirect, and double-indirect block
// pointers to reassemble a file's full contents, then truncates to
// i_size_lo. Triple-indirect is not implemented: none of the files this
// package targets (flatkc ~4MB, rootfs.gz ~56MB, datafs.tar.gz ~14MB)
// require it -- double-indirect alone addresses (blockSize/4)^2 blocks,
// e.g. 256MB at a 4K block size.
func (f *FS) readInodeDataIndirect(num uint32, in *inode) ([]byte, error) {
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

// ExtractAll writes the full filesystem tree (directories, regular files,
// and symlinks) under destDir. It exists for rootfs payloads that are
// filesystem images rather than tar archives (FortiOS 8.0 VM images).
func (f *FS) ExtractAll(destDir string) error {
	return f.extractDir("", destDir)
}

func (f *FS) extractDir(relPath, destDir string) error {
	entries, err := f.ReadDir(relPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		childRel := e.Name
		if relPath != "" {
			childRel = relPath + "/" + e.Name
		}
		target := filepath.Join(destDir, e.Name)
		if e.IsDir {
			if err := f.extractDir(childRel, target); err != nil {
				return err
			}
			continue
		}
		in, err := f.readInode(e.Inode)
		if err != nil {
			continue // unreadable entry: skip rather than abort the dump
		}
		switch in.mode & s_IFMT {
		case s_IFREG:
			data, err := f.ReadFile(childRel)
			if err != nil {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(target, data, 0o644); err != nil {
				return err
			}
		case s_IFLNK:
			targetBytes, err := f.readInodeFast(e.Inode)
			if err == nil && len(targetBytes) > 0 {
				_ = os.Remove(target)
				_ = os.Symlink(string(targetBytes), target)
			}
		}
	}
	return nil
}

// readInodeFast returns an inode's raw content bytes (fast symlink targets
// are stored inline in the i_block area; slow ones in a data block).
func (f *FS) readInodeFast(num uint32) ([]byte, error) {
	in, err := f.readInode(num)
	if err != nil {
		return nil, err
	}
	raw := in.blockRaw[:]
	if uint64(in.sizeLo) <= uint64(len(raw)) {
		return raw[:in.sizeLo], nil
	}
	return f.readInodeData(num, in)
}
