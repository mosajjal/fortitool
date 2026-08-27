// Package diskimage is a minimal, read-only, pure-Go ext2/ext3 filesystem
// reader. It exists to replace `dd | debugfs -R rdump` in the firmware
// unpack pipeline: FortiOS firmware images are a 512-byte MBR sector
// followed by a plain ext3 "FORTIOS" volume (no extents, no 64bit feature,
// no metadata_csum, no journal replay needed since we never write). This
// package only needs to resolve a handful of files living directly in the
// root directory, so it implements just enough of ext2 to do that: the
// classic 32-byte block group descriptor, 128-byte inodes, and direct /
// single-indirect / double-indirect / triple-indirect block mapping.
package diskimage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrNotFound distinguishes an optional absent filesystem member from a
// malformed or unreadable filesystem entry.
var ErrNotFound = errors.New("diskimage: file not found")

var errCannotMaterialise = errors.New("diskimage: inode cannot be materialised on this platform")

const (
	superblockOffset = 1024
	superblockSize   = 1024
	ext2Magic        = 0xEF53

	bgDescSize = 32 // classic (non-64bit) block group descriptor

	defaultInodeSize = 128 // GOOD_OLD_REV inodes are always 128 bytes
	maxRevisionLevel = 1   // EXT2_DYNAMIC_REV

	rootInode = 2

	s_IFMT   = 0xF000
	s_IFIFO  = 0x1000
	s_IFCHR  = 0x2000
	s_IFDIR  = 0x4000
	s_IFBLK  = 0x6000
	s_IFREG  = 0x8000
	s_IFLNK  = 0xA000
	s_IFSOCK = 0xC000

	dirEntryHeaderSize = 8

	extFeatureIncompatFiletype = 0x0002
	extFeatureIncompatExtents  = 0x0040
	extSupportedIncompat       = extFeatureIncompatFiletype | extFeatureIncompatExtents
	extFeatureROCompatBigalloc = 0x0200
	extGroupFlagInodeUninit    = 0x0001

	inodeFlagExtents    = 0x00080000
	inodeFlagInlineData = 0x10000000

	maxExtentDepth               = 5
	maxExtentTreeEntries         = 1 << 20
	maxDirectorySize             = 64 << 20
	maxDirectoryEntries          = 1 << 20
	maxDirectoryDepth            = 256
	maxDirectoryTreeBytes uint64 = 512 << 20
	maxSymlinkSize        uint32 = 4096

	nDirect       = 12
	iBlockSingle  = 12
	iBlockDouble  = 13
	iBlockTriple  = 14
	numIBlockPtrs = 15
)

type superblock struct {
	inodesCount     uint32
	blocksCount     uint32
	firstDataBlock  uint32
	logBlockSize    uint32
	inodesPerGroup  uint32
	blocksPerGroup  uint32
	revLevel        uint32
	inodeSize       uint16
	blockSize       uint32
	featureCompat   uint32
	featureIncompat uint32
	featureROCompat uint32
}

type groupDesc struct {
	inodeBitmapBlock uint32
	inodeTableBlock  uint32
	flags            uint16
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
	size := int64(len(s.data))
	if off < 0 || off > size || int64(len(p)) > size-off {
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
	if s.sz < 0 || off < 0 || off > s.sz || int64(len(p)) > s.sz-off {
		return fmt.Errorf("diskimage: read at %d (%d bytes) past end of image (%d bytes)", off, len(p), s.sz)
	}
	n, err := s.r.ReadAt(p, off)
	if err != nil {
		return fmt.Errorf("diskimage: read at %d (%d bytes): %w", off, len(p), err)
	}
	if n != len(p) {
		return fmt.Errorf("diskimage: read at %d returned %d of %d bytes: %w", off, n, len(p), io.ErrUnexpectedEOF)
	}
	return nil
}

// FS is a read-only handle on a parsed ext2/ext3/ext4 filesystem image.
type FS struct {
	src         source
	sb          superblock
	groupCount  uint32
	gdtOffset   uint64
	gdtEndBlock uint64
	fsSize      uint64
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
	sourceSize := src.size()
	if sourceSize < superblockOffset+superblockSize {
		return nil, fmt.Errorf("diskimage: image too small (%d bytes) to contain a superblock", sourceSize)
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
		inodesCount:     binary.LittleEndian.Uint32(sbBytes[0:4]),
		blocksCount:     binary.LittleEndian.Uint32(sbBytes[4:8]),
		firstDataBlock:  binary.LittleEndian.Uint32(sbBytes[20:24]),
		logBlockSize:    binary.LittleEndian.Uint32(sbBytes[24:28]),
		blocksPerGroup:  binary.LittleEndian.Uint32(sbBytes[32:36]),
		inodesPerGroup:  binary.LittleEndian.Uint32(sbBytes[40:44]),
		revLevel:        binary.LittleEndian.Uint32(sbBytes[76:80]),
		featureCompat:   binary.LittleEndian.Uint32(sbBytes[92:96]),
		featureIncompat: binary.LittleEndian.Uint32(sbBytes[96:100]),
		featureROCompat: binary.LittleEndian.Uint32(sbBytes[100:104]),
	}
	if sb.logBlockSize > 6 {
		return nil, fmt.Errorf("diskimage: unsupported block-size exponent %d", sb.logBlockSize)
	}
	if sb.revLevel > maxRevisionLevel {
		return nil, fmt.Errorf("diskimage: unsupported filesystem revision %d", sb.revLevel)
	}
	if sb.revLevel == 0 && (sb.featureCompat != 0 || sb.featureIncompat != 0 || sb.featureROCompat != 0) {
		return nil, fmt.Errorf("diskimage: revision 0 filesystem has unsupported feature flags")
	}
	sb.blockSize = uint32(1024) << sb.logBlockSize
	if unsupported := sb.featureIncompat &^ uint32(extSupportedIncompat); unsupported != 0 {
		return nil, fmt.Errorf("diskimage: unsupported incompatible filesystem features 0x%08X", unsupported)
	}
	if sb.featureROCompat&extFeatureROCompatBigalloc != 0 {
		return nil, fmt.Errorf("diskimage: unsupported bigalloc filesystem layout")
	}

	if sb.revLevel == 0 {
		sb.inodeSize = defaultInodeSize
	} else {
		sb.inodeSize = binary.LittleEndian.Uint16(sbBytes[88:90])
	}

	if sb.inodesCount < rootInode || sb.blocksCount == 0 || sb.blocksPerGroup == 0 || sb.inodesPerGroup == 0 {
		return nil, fmt.Errorf("diskimage: invalid zero or undersized filesystem geometry")
	}
	if (sb.blockSize == 1024 && sb.firstDataBlock != 1) || (sb.blockSize > 1024 && sb.firstDataBlock != 0) {
		return nil, fmt.Errorf("diskimage: first data block %d is invalid for %d-byte blocks", sb.firstDataBlock, sb.blockSize)
	}
	if sb.blocksCount <= sb.firstDataBlock {
		return nil, fmt.Errorf("diskimage: block count %d does not extend past first data block %d", sb.blocksCount, sb.firstDataBlock)
	}
	bitmapCapacity := uint64(sb.blockSize) * 8
	if uint64(sb.blocksPerGroup) > bitmapCapacity || uint64(sb.inodesPerGroup) > bitmapCapacity {
		return nil, fmt.Errorf("diskimage: block/inode group geometry exceeds bitmap capacity")
	}
	if sb.revLevel == 0 {
		if sb.inodeSize != defaultInodeSize {
			return nil, fmt.Errorf("diskimage: revision 0 inode size %d is invalid", sb.inodeSize)
		}
	} else if sb.inodeSize < defaultInodeSize || uint32(sb.inodeSize) > sb.blockSize || !isPowerOfTwo(uint32(sb.inodeSize)) {
		return nil, fmt.Errorf("diskimage: invalid inode size %d for %d-byte blocks", sb.inodeSize, sb.blockSize)
	}

	dataBlocks := uint64(sb.blocksCount - sb.firstDataBlock)
	numGroups64 := ceilDiv(dataBlocks, uint64(sb.blocksPerGroup))
	if numGroups64 == 0 || numGroups64 > uint64(^uint32(0)) {
		return nil, fmt.Errorf("diskimage: invalid block group count %d", numGroups64)
	}
	inodeCapacity, ok := checkedMul(numGroups64, uint64(sb.inodesPerGroup))
	if !ok || uint64(sb.inodesCount) > inodeCapacity {
		return nil, fmt.Errorf("diskimage: inode count %d exceeds group capacity %d", sb.inodesCount, inodeCapacity)
	}
	fsSize, ok := checkedMul(uint64(sb.blocksCount), uint64(sb.blockSize))
	if !ok || fsSize > uint64(sourceSize) {
		return nil, fmt.Errorf("diskimage: filesystem geometry requires %d bytes, image window has %d", fsSize, sourceSize)
	}

	// Block group descriptor table starts in the block immediately
	// following the superblock's own block. For a 1024-byte block size
	// the superblock occupies block 1, so the table starts at block 2;
	// for larger block sizes the superblock lives inside block 0, so the
	// table starts at block 1.
	gdtBlock := uint64(sb.firstDataBlock) + 1
	gdtOffset, ok := checkedMul(gdtBlock, uint64(sb.blockSize))
	if !ok {
		return nil, fmt.Errorf("diskimage: block group descriptor offset overflows")
	}
	gdtSize, ok := checkedMul(numGroups64, uint64(bgDescSize))
	if !ok || !rangeWithin(gdtOffset, gdtSize, fsSize) {
		return nil, fmt.Errorf("diskimage: block group descriptor table (offset %d, %d groups) runs past filesystem boundary (%d bytes)", gdtOffset, numGroups64, fsSize)
	}
	gdtEndBlock, ok := checkedAdd(gdtBlock, ceilDiv(gdtSize, uint64(sb.blockSize)))
	if !ok || gdtEndBlock > uint64(sb.blocksCount) {
		return nil, fmt.Errorf("diskimage: block group descriptor table block range overflows")
	}

	fs := &FS{src: src, sb: sb, groupCount: uint32(numGroups64), gdtOffset: gdtOffset, gdtEndBlock: gdtEndBlock, fsSize: fsSize}
	root, err := fs.readInode(rootInode)
	if err != nil {
		return nil, fmt.Errorf("diskimage: invalid root inode: %w", err)
	}
	if !fs.isDir(root) {
		return nil, fmt.Errorf("diskimage: root inode is not a directory (mode 0x%04X)", root.mode)
	}
	return fs, nil
}

type inode struct {
	mode     uint16
	sizeLo   uint32
	flags    uint32
	block    [numIBlockPtrs]uint32
	blockRaw [60]byte // raw i_block bytes, needed for extent-tree parsing
}

func (f *FS) readGroupDesc(group uint32) (groupDesc, error) {
	if group >= f.groupCount {
		return groupDesc{}, fmt.Errorf("diskimage: group %d is outside group count %d", group, f.groupCount)
	}
	delta, ok := checkedMul(uint64(group), uint64(bgDescSize))
	if !ok {
		return groupDesc{}, fmt.Errorf("diskimage: group descriptor %d offset overflows", group)
	}
	off, ok := checkedAdd(f.gdtOffset, delta)
	if !ok || !rangeWithin(off, bgDescSize, f.fsSize) {
		return groupDesc{}, fmt.Errorf("diskimage: group descriptor %d runs past filesystem boundary", group)
	}
	raw := make([]byte, bgDescSize)
	if err := f.readAt(raw, off); err != nil {
		return groupDesc{}, fmt.Errorf("diskimage: reading group descriptor %d: %w", group, err)
	}
	desc := groupDesc{
		inodeBitmapBlock: binary.LittleEndian.Uint32(raw[4:8]),
		inodeTableBlock:  binary.LittleEndian.Uint32(raw[8:12]),
		flags:            binary.LittleEndian.Uint16(raw[18:20]),
	}
	if desc.flags&extGroupFlagInodeUninit != 0 {
		return groupDesc{}, fmt.Errorf("diskimage: group %d inode bitmap and table are uninitialised", group)
	}
	if desc.inodeBitmapBlock == 0 || desc.inodeBitmapBlock >= f.sb.blocksCount {
		return groupDesc{}, fmt.Errorf("diskimage: group %d inode bitmap block %d is outside filesystem", group, desc.inodeBitmapBlock)
	}
	if desc.inodeTableBlock == 0 || desc.inodeTableBlock >= f.sb.blocksCount {
		return groupDesc{}, fmt.Errorf("diskimage: group %d inode table block %d is outside filesystem", group, desc.inodeTableBlock)
	}
	firstInode, ok := checkedMul(uint64(group), uint64(f.sb.inodesPerGroup))
	if !ok || firstInode >= uint64(f.sb.inodesCount) {
		return groupDesc{}, fmt.Errorf("diskimage: group %d has no addressable inodes", group)
	}
	tableBytes, ok := checkedMul(uint64(f.sb.inodesPerGroup), uint64(f.sb.inodeSize))
	if !ok {
		return groupDesc{}, fmt.Errorf("diskimage: group %d inode table size overflows", group)
	}
	tableBlocks := ceilDiv(tableBytes, uint64(f.sb.blockSize))
	tableEnd, ok := checkedAdd(uint64(desc.inodeTableBlock), tableBlocks)
	if !ok || tableEnd > uint64(f.sb.blocksCount) {
		return groupDesc{}, fmt.Errorf("diskimage: group %d inode table runs past filesystem block count", group)
	}
	groupStart, ok := checkedMul(uint64(group), uint64(f.sb.blocksPerGroup))
	if !ok {
		return groupDesc{}, fmt.Errorf("diskimage: group %d block range overflows", group)
	}
	groupStart, ok = checkedAdd(uint64(f.sb.firstDataBlock), groupStart)
	if !ok {
		return groupDesc{}, fmt.Errorf("diskimage: group %d block range overflows", group)
	}
	groupEnd, ok := checkedAdd(groupStart, uint64(f.sb.blocksPerGroup))
	if !ok || groupEnd > uint64(f.sb.blocksCount) {
		groupEnd = uint64(f.sb.blocksCount)
	}
	if uint64(desc.inodeBitmapBlock) < groupStart || uint64(desc.inodeBitmapBlock) >= groupEnd || uint64(desc.inodeTableBlock) < groupStart || tableEnd > groupEnd {
		return groupDesc{}, fmt.Errorf("diskimage: group %d inode metadata lies outside its block range [%d,%d)", group, groupStart, groupEnd)
	}
	if group == 0 && (uint64(desc.inodeBitmapBlock) < f.gdtEndBlock || uint64(desc.inodeTableBlock) < f.gdtEndBlock) {
		return groupDesc{}, fmt.Errorf("diskimage: group 0 inode metadata overlaps the primary superblock or descriptor table")
	}
	if uint64(desc.inodeBitmapBlock) >= uint64(desc.inodeTableBlock) && uint64(desc.inodeBitmapBlock) < tableEnd {
		return groupDesc{}, fmt.Errorf("diskimage: group %d inode bitmap overlaps inode table", group)
	}
	return desc, nil
}

func (f *FS) readAt(p []byte, off uint64) error {
	if !rangeWithin(off, uint64(len(p)), f.fsSize) || off > uint64(^uint64(0)>>1) {
		return fmt.Errorf("diskimage: read at %d (%d bytes) past filesystem boundary (%d bytes)", off, len(p), f.fsSize)
	}
	return f.src.at(p, int64(off))
}

func (f *FS) readInode(num uint32) (*inode, error) {
	if num == 0 || num > f.sb.inodesCount {
		return nil, fmt.Errorf("diskimage: inode %d is outside inode count %d", num, f.sb.inodesCount)
	}
	group := (num - 1) / f.sb.inodesPerGroup
	index := (num - 1) % f.sb.inodesPerGroup
	desc, err := f.readGroupDesc(group)
	if err != nil {
		return nil, fmt.Errorf("diskimage: inode %d group metadata: %w", num, err)
	}
	bitmapBase, ok := checkedMul(uint64(desc.inodeBitmapBlock), uint64(f.sb.blockSize))
	if !ok {
		return nil, fmt.Errorf("diskimage: inode %d bitmap offset overflows", num)
	}
	bitmapOff, ok := checkedAdd(bitmapBase, uint64(index/8))
	if !ok {
		return nil, fmt.Errorf("diskimage: inode %d bitmap offset overflows", num)
	}
	var allocated [1]byte
	if err := f.readAt(allocated[:], bitmapOff); err != nil {
		return nil, fmt.Errorf("diskimage: reading inode %d allocation bitmap: %w", num, err)
	}
	if allocated[0]&(1<<uint(index%8)) == 0 {
		return nil, fmt.Errorf("diskimage: inode %d is not allocated", num)
	}
	tableBase, ok := checkedMul(uint64(desc.inodeTableBlock), uint64(f.sb.blockSize))
	if !ok {
		return nil, fmt.Errorf("diskimage: inode %d table offset overflows", num)
	}
	inodeDelta, ok := checkedMul(uint64(index), uint64(f.sb.inodeSize))
	if !ok {
		return nil, fmt.Errorf("diskimage: inode %d table offset overflows", num)
	}
	off, ok := checkedAdd(tableBase, inodeDelta)
	if !ok || !rangeWithin(off, defaultInodeSize, f.fsSize) {
		return nil, fmt.Errorf("diskimage: inode %d at offset %d runs past filesystem boundary", num, off)
	}
	raw := make([]byte, 128)
	if err := f.readAt(raw, off); err != nil {
		return nil, fmt.Errorf("diskimage: reading inode %d: %w", num, err)
	}

	in := &inode{
		mode:   binary.LittleEndian.Uint16(raw[0:2]),
		sizeLo: binary.LittleEndian.Uint32(raw[4:8]),
		flags:  binary.LittleEndian.Uint32(raw[32:36]),
	}
	if in.mode&s_IFMT == s_IFREG && binary.LittleEndian.Uint32(raw[108:112]) != 0 {
		return nil, fmt.Errorf("diskimage: inode %d uses an unsupported 64-bit file size", num)
	}
	for i := 0; i < numIBlockPtrs; i++ {
		in.block[i] = binary.LittleEndian.Uint32(raw[40+i*4 : 44+i*4])
	}
	copy(in.blockRaw[:], raw[40:100])
	return in, nil
}

func (f *FS) isDir(in *inode) bool { return in.mode&s_IFMT == s_IFDIR }
func (f *FS) isReg(in *inode) bool { return in.mode&s_IFMT == s_IFREG }

func (f *FS) readBlock(num uint32) ([]byte, error) {
	if num == 0 {
		return make([]byte, f.sb.blockSize), nil // sparse hole
	}
	if num >= f.sb.blocksCount {
		return nil, fmt.Errorf("diskimage: block %d is outside filesystem block count %d", num, f.sb.blocksCount)
	}
	off, ok := checkedMul(uint64(num), uint64(f.sb.blockSize))
	if !ok || !rangeWithin(off, uint64(f.sb.blockSize), f.fsSize) {
		return nil, fmt.Errorf("diskimage: block %d runs past filesystem boundary (%d bytes)", num, f.fsSize)
	}
	buf := make([]byte, f.sb.blockSize)
	if err := f.readAt(buf, off); err != nil {
		return nil, fmt.Errorf("diskimage: reading block %d: %w", num, err)
	}
	return buf, nil
}

func (f *FS) blockPointers(blockNum uint32) ([]uint32, error) {
	raw, err := f.readBlock(blockNum)
	if err != nil {
		return nil, err
	}
	n := len(raw) / 4
	ptrs := make([]uint32, n)
	for i := 0; i < n; i++ {
		ptrs[i] = binary.LittleEndian.Uint32(raw[i*4 : i*4+4])
	}
	return ptrs, nil
}

const extentMagic = 0xF30A

// readInodeData dispatches between the two on-disk block-mapping schemes:
// ext2/3-style direct+indirect pointers and ext4-style extent trees (used
// by newer images such as FortiOS 8.0's ext4 rootfs).
func (f *FS) readInodeData(num uint32, in *inode) ([]byte, error) {
	if in.flags&inodeFlagInlineData != 0 {
		return nil, fmt.Errorf("diskimage: inode %d uses unsupported inline data", num)
	}
	if in.flags&inodeFlagExtents != 0 {
		if f.sb.featureIncompat&extFeatureIncompatExtents == 0 {
			return nil, fmt.Errorf("diskimage: inode %d has extent flag without filesystem extent feature", num)
		}
		if binary.LittleEndian.Uint16(in.blockRaw[0:2]) != extentMagic {
			return nil, fmt.Errorf("diskimage: inode %d has extent flag with invalid root magic", num)
		}
		return f.readInodeDataExtents(num, in)
	}
	return f.readInodeDataIndirect(num, in)
}

// extent is one flattened leaf entry of an extent tree.
type extent struct {
	logical  uint32 // first logical block
	physical uint32 // first physical block
	count    uint32 // number of blocks
	uninit   bool
}

// collectExtents walks the extent tree rooted at root (the raw i_block
// bytes) and returns its leaf extents in logical order.
func (f *FS) collectExtents(root []byte, logicalBlocks uint64) ([]extent, error) {
	const (
		headerSize = 12
		entrySize  = 12
	)
	if len(root) < headerSize {
		return nil, fmt.Errorf("diskimage: truncated extent root")
	}
	rootDepth := binary.LittleEndian.Uint16(root[6:8])
	if rootDepth > maxExtentDepth {
		return nil, fmt.Errorf("diskimage: extent depth %d exceeds supported maximum %d", rootDepth, maxExtentDepth)
	}

	var leaves []extent
	visited := make(map[uint32]struct{})
	var walkedEntries uint64
	var walk func([]byte, uint16, uint64, uint64) error
	walk = func(node []byte, expectedDepth uint16, lower, upper uint64) error {
		if len(node) < headerSize || binary.LittleEndian.Uint16(node[0:2]) != extentMagic {
			return fmt.Errorf("diskimage: corrupt extent header magic")
		}
		entries := uint64(binary.LittleEndian.Uint16(node[2:4]))
		maximum := uint64(binary.LittleEndian.Uint16(node[4:6]))
		depth := binary.LittleEndian.Uint16(node[6:8])
		capacity := uint64((len(node) - headerSize) / entrySize)
		if depth != expectedDepth || depth > maxExtentDepth {
			return fmt.Errorf("diskimage: corrupt extent depth %d, expected %d", depth, expectedDepth)
		}
		if maximum == 0 || maximum > capacity || entries > maximum {
			return fmt.Errorf("diskimage: corrupt extent header (%d entries, maximum %d, capacity %d)", entries, maximum, capacity)
		}
		if depth > 0 && entries == 0 {
			return fmt.Errorf("diskimage: empty internal extent node")
		}
		var ok bool
		walkedEntries, ok = checkedAdd(walkedEntries, entries)
		if !ok || walkedEntries > maxExtentTreeEntries {
			return fmt.Errorf("diskimage: extent tree exceeds %d entries", maxExtentTreeEntries)
		}

		if depth == 0 {
			previousEnd := lower
			for i := uint64(0); i < entries; i++ {
				off := headerSize + int(i)*entrySize
				raw := node[off : off+entrySize]
				logical := uint64(binary.LittleEndian.Uint32(raw[0:4]))
				encodedLen := binary.LittleEndian.Uint16(raw[4:6])
				uninit := encodedLen > 0x8000
				count := uint64(encodedLen)
				if uninit {
					count -= 0x8000
				}
				if count == 0 {
					return fmt.Errorf("diskimage: zero-length extent at logical block %d", logical)
				}
				logicalEnd, ok := checkedAdd(logical, count)
				if !ok || logical < lower || logical < previousEnd || logicalEnd > upper || logicalEnd > uint64(^uint32(0))+1 {
					return fmt.Errorf("diskimage: overlapping or out-of-range extent at logical block %d", logical)
				}
				physical, err := decodeExtentBlock(binary.LittleEndian.Uint16(raw[6:8]), binary.LittleEndian.Uint32(raw[8:12]))
				if err != nil {
					return err
				}
				physicalEnd, ok := checkedAdd(uint64(physical), count)
				if physical == 0 || !ok || physicalEnd > uint64(f.sb.blocksCount) {
					return fmt.Errorf("diskimage: extent at logical block %d runs outside filesystem blocks", logical)
				}
				leaves = append(leaves, extent{logical: uint32(logical), physical: physical, count: uint32(count), uninit: uninit})
				previousEnd = logicalEnd
			}
			return nil
		}

		keys := make([]uint64, entries)
		blocks := make([]uint32, entries)
		for i := uint64(0); i < entries; i++ {
			off := headerSize + int(i)*entrySize
			raw := node[off : off+entrySize]
			key := uint64(binary.LittleEndian.Uint32(raw[0:4]))
			if key < lower || key >= upper || (i > 0 && key <= keys[i-1]) {
				return fmt.Errorf("diskimage: unordered extent index at logical block %d", key)
			}
			block, err := decodeExtentBlock(binary.LittleEndian.Uint16(raw[8:10]), binary.LittleEndian.Uint32(raw[4:8]))
			if err != nil {
				return err
			}
			if block == 0 || block >= f.sb.blocksCount {
				return fmt.Errorf("diskimage: extent index block %d is outside filesystem", block)
			}
			keys[i] = key
			blocks[i] = block
		}
		for i, block := range blocks {
			if _, ok := visited[block]; ok {
				return fmt.Errorf("diskimage: extent tree reuses block %d", block)
			}
			visited[block] = struct{}{}
			nodeUpper := upper
			if i+1 < len(keys) {
				nodeUpper = keys[i+1]
			}
			child, err := f.readBlock(block)
			if err != nil {
				return fmt.Errorf("diskimage: reading extent index node at block %d: %w", block, err)
			}
			if err := walk(child, depth-1, keys[i], nodeUpper); err != nil {
				return err
			}
		}
		return nil
	}
	if logicalBlocks > uint64(^uint32(0))+1 {
		return nil, fmt.Errorf("diskimage: extent logical block count %d overflows", logicalBlocks)
	}
	if err := walk(root, rootDepth, 0, logicalBlocks); err != nil {
		return nil, err
	}
	return leaves, nil
}

func decodeExtentBlock(hi uint16, lo uint32) (uint32, error) {
	if hi != 0 {
		return 0, fmt.Errorf("diskimage: 48-bit extent block address is unsupported")
	}
	return lo, nil
}

func (f *FS) readInodeDataExtents(num uint32, in *inode) ([]byte, error) {
	blockSize := uint64(f.sb.blockSize)
	maxInt := uint64(^uint(0) >> 1)
	size := uint64(in.sizeLo)
	if blockSize == 0 || blockSize > maxInt || f.src.size() < 0 {
		return nil, fmt.Errorf("diskimage: inode %d has invalid block or source size", num)
	}
	if size > maxInt {
		return nil, fmt.Errorf("%w: inode %d size %d exceeds platform byte-slice capacity", errCannotMaterialise, num, size)
	}
	needed := ceilDiv(size, blockSize)

	extents, err := f.collectExtents(in.blockRaw[:], needed)
	if err != nil {
		return nil, fmt.Errorf("diskimage: inode %d: %w", num, err)
	}

	out := make([]byte, 0, int(size))
	var written uint64
	emitHole := func(blocks uint64) error {
		if blocks > needed-written {
			blocks = needed - written
		}
		bytesToAppend, ok := checkedMul(blocks, blockSize)
		if !ok {
			return fmt.Errorf("diskimage: inode %d sparse extent size overflows", num)
		}
		if remaining := size - uint64(len(out)); bytesToAppend > remaining {
			bytesToAppend = remaining
		}
		out = append(out, make([]byte, int(bytesToAppend))...)
		written += blocks
		return nil
	}

	for _, e := range extents {
		if written >= needed {
			break
		}
		logical := uint64(e.logical)
		if logical > written {
			if err := emitHole(logical - written); err != nil {
				return nil, err
			}
			if written >= needed {
				break
			}
		}
		if logical != written {
			return nil, fmt.Errorf("diskimage: inode %d extent order does not match logical output", num)
		}
		blocks := uint64(e.count)
		if blocks > needed-written {
			blocks = needed - written
		}
		if e.uninit {
			if err := emitHole(blocks); err != nil {
				return nil, err
			}
			continue
		}
		for i := uint64(0); i < blocks; i++ {
			blockNum, ok := checkedAdd(uint64(e.physical), i)
			if !ok || blockNum > uint64(^uint32(0)) {
				return nil, fmt.Errorf("diskimage: inode %d extent block number overflows", num)
			}
			block, err := f.readBlock(uint32(blockNum))
			if err != nil {
				return nil, fmt.Errorf("diskimage: inode %d extent data: %w", num, err)
			}
			n := blockSize
			if remaining := size - uint64(len(out)); n > remaining {
				n = remaining
			}
			out = append(out, block[:int(n)]...)
			written++
		}
	}
	if written < needed {
		if err := emitHole(needed - written); err != nil {
			return nil, err
		}
	}

	if uint64(len(out)) != size {
		return nil, fmt.Errorf("diskimage: inode %d size %d reconstructed as %d bytes", num, size, len(out))
	}
	return out, nil
}

// readInodeDataIndirect walks classic direct through triple-indirect block
// pointers, bounded by i_size_lo rather than unused pointer-table capacity.
func (f *FS) readInodeDataIndirect(num uint32, in *inode) ([]byte, error) {
	blockSize := uint64(f.sb.blockSize)
	maxInt := uint64(^uint(0) >> 1)
	if blockSize == 0 || blockSize%4 != 0 || blockSize > maxInt {
		return nil, fmt.Errorf("diskimage: inode %d has invalid block size %d", num, blockSize)
	}
	size := uint64(in.sizeLo)
	ptrsPerBlock := blockSize / 4
	needed := size / blockSize
	if size%blockSize != 0 {
		needed++
	}
	if f.src.size() < 0 {
		return nil, fmt.Errorf("diskimage: inode %d has invalid source size %d", num, f.src.size())
	}
	if size > maxInt {
		return nil, fmt.Errorf("%w: inode %d size %d exceeds platform byte-slice capacity", errCannotMaterialise, num, size)
	}
	singleCapacity := ptrsPerBlock
	doubleCapacity, ok := checkedMul(ptrsPerBlock, ptrsPerBlock)
	if !ok {
		return nil, fmt.Errorf("diskimage: inode %d double-indirect capacity overflows", num)
	}
	tripleCapacity, ok := checkedMul(doubleCapacity, ptrsPerBlock)
	if !ok {
		return nil, fmt.Errorf("diskimage: inode %d triple-indirect capacity overflows", num)
	}
	maxBlocks, ok := checkedAdd(uint64(nDirect), singleCapacity, doubleCapacity, tripleCapacity)
	if !ok || needed > maxBlocks {
		return nil, fmt.Errorf("diskimage: inode %d size %d exceeds classic block-map capacity", num, size)
	}

	out := make([]byte, 0, int(size))
	var written uint64
	visitedIndirect := make(map[uint32]struct{})

	appendBlock := func(b uint32) error {
		if written >= needed {
			return nil
		}
		remaining := size - uint64(len(out))
		n := blockSize
		if n > remaining {
			n = remaining
		}
		if b == 0 {
			out = append(out, make([]byte, int(n))...)
		} else {
			block, err := f.readBlock(b)
			if err != nil {
				return err
			}
			out = append(out, block[:int(n)]...)
		}
		written++
		return nil
	}
	appendHole := func(n uint64) error {
		if written >= needed {
			return nil
		}
		remaining := needed - written
		if n > remaining {
			n = remaining
		}
		bytesToAppend, ok := checkedMul(n, blockSize)
		if !ok {
			return fmt.Errorf("sparse subtree size overflows")
		}
		if tail := size - uint64(len(out)); bytesToAppend > tail {
			bytesToAppend = tail
		}
		if bytesToAppend > maxInt {
			return fmt.Errorf("sparse subtree allocation exceeds platform limit")
		}
		out = append(out, make([]byte, int(bytesToAppend))...)
		written += n
		return nil
	}

	for i := 0; i < nDirect && written < needed; i++ {
		if err := appendBlock(in.block[i]); err != nil {
			return nil, fmt.Errorf("diskimage: inode %d direct block %d: %w", num, i, err)
		}
	}

	var walkIndirect func(uint32, int, uint64) error
	walkIndirect = func(pointer uint32, level int, capacity uint64) error {
		if written >= needed {
			return nil
		}
		if level < 1 || level > 3 {
			return fmt.Errorf("invalid indirect level %d", level)
		}
		if pointer == 0 {
			return appendHole(capacity)
		}
		if _, ok := visitedIndirect[pointer]; ok {
			return fmt.Errorf("indirect tree reuses block %d", pointer)
		}
		visitedIndirect[pointer] = struct{}{}
		ptrs, err := f.blockPointers(pointer)
		if err != nil {
			return err
		}
		childCapacity := uint64(1)
		if level > 1 {
			childCapacity = capacity / ptrsPerBlock
		}
		for _, child := range ptrs {
			if written >= needed {
				break
			}
			if level == 1 {
				if err := appendBlock(child); err != nil {
					return err
				}
			} else if err := walkIndirect(child, level-1, childCapacity); err != nil {
				return err
			}
		}
		return nil
	}

	levels := []struct {
		pointer  uint32
		level    int
		capacity uint64
	}{
		{in.block[iBlockSingle], 1, singleCapacity},
		{in.block[iBlockDouble], 2, doubleCapacity},
		{in.block[iBlockTriple], 3, tripleCapacity},
	}
	for _, indirect := range levels {
		if written >= needed {
			break
		}
		if err := walkIndirect(indirect.pointer, indirect.level, indirect.capacity); err != nil {
			return nil, fmt.Errorf("diskimage: inode %d level-%d indirect block: %w", num, indirect.level, err)
		}
	}

	if uint64(len(out)) != size {
		return nil, fmt.Errorf("diskimage: inode %d size %d reconstructed as %d bytes", num, size, len(out))
	}
	return out, nil
}

func checkedMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}

func checkedAdd(values ...uint64) (uint64, bool) {
	var sum uint64
	for _, value := range values {
		if value > ^uint64(0)-sum {
			return 0, false
		}
		sum += value
	}
	return sum, true
}

func ceilDiv(value, divisor uint64) uint64 {
	quotient := value / divisor
	if value%divisor != 0 {
		quotient++
	}
	return quotient
}

func rangeWithin(off, length, limit uint64) bool {
	return off <= limit && length <= limit-off
}

func isPowerOfTwo(value uint32) bool {
	return value != 0 && value&(value-1) == 0
}

// DirEntry describes one entry returned by ReadDir.
type DirEntry struct {
	Name  string
	IsDir bool
	Inode uint32
	Size  uint64
}

func (f *FS) readDirEntries(dirInodeNum uint32) ([]DirEntry, error) {
	return f.readDirEntriesBudgetMode(dirInodeNum, nil, nil, false)
}

func (f *FS) readDirEntriesBudget(dirInodeNum uint32, recordBudget, byteBudget *uint64) ([]DirEntry, error) {
	return f.readDirEntriesBudgetMode(dirInodeNum, recordBudget, byteBudget, false)
}

func (f *FS) readDirEntriesBudgetMode(dirInodeNum uint32, recordBudget, byteBudget *uint64, tolerateUnreadableLeaves bool) ([]DirEntry, error) {
	in, err := f.readInode(dirInodeNum)
	if err != nil {
		return nil, fmt.Errorf("diskimage: reading directory inode %d: %w", dirInodeNum, err)
	}
	if !f.isDir(in) {
		return nil, fmt.Errorf("diskimage: inode %d is not a directory (mode 0x%04X)", dirInodeNum, in.mode)
	}
	if uint64(in.sizeLo) > maxDirectorySize {
		return nil, fmt.Errorf("diskimage: directory inode %d size %d exceeds limit %d", dirInodeNum, in.sizeLo, maxDirectorySize)
	}
	if f.sb.blockSize < dirEntryHeaderSize || in.sizeLo == 0 || in.sizeLo%f.sb.blockSize != 0 {
		return nil, fmt.Errorf("diskimage: directory inode %d has invalid size %d for block size %d", dirInodeNum, in.sizeLo, f.sb.blockSize)
	}
	if byteBudget != nil {
		total, ok := checkedAdd(*byteBudget, uint64(in.sizeLo))
		if !ok || total > maxDirectoryTreeBytes {
			return nil, fmt.Errorf("diskimage: directory traversal exceeds byte limit %d", maxDirectoryTreeBytes)
		}
		*byteBudget = total
	}

	data, err := f.readInodeData(dirInodeNum, in)
	if err != nil {
		return nil, fmt.Errorf("diskimage: reading directory data for inode %d: %w", dirInodeNum, err)
	}

	var entries []DirEntry
	blockSize := int(f.sb.blockSize)
	var entryCount uint64
	for blockStart := 0; blockStart+dirEntryHeaderSize <= len(data); blockStart += blockSize {
		blockEnd := blockStart + blockSize
		if blockEnd > len(data) {
			blockEnd = len(data)
		}
		off := blockStart
		for off+dirEntryHeaderSize <= blockEnd {
			entryCount++
			if entryCount > maxDirectoryEntries {
				return nil, fmt.Errorf("diskimage: directory inode %d exceeds %d entries", dirInodeNum, maxDirectoryEntries)
			}
			if recordBudget != nil {
				total, ok := checkedAdd(*recordBudget, 1)
				if !ok || total > maxDirectoryEntries {
					return nil, fmt.Errorf("diskimage: directory traversal exceeds record limit %d", maxDirectoryEntries)
				}
				*recordBudget = total
			}
			entInode := binary.LittleEndian.Uint32(data[off : off+4])
			rawRecLen := binary.LittleEndian.Uint16(data[off+4 : off+6])
			recLen := uint32(rawRecLen)
			if f.sb.blockSize == 65536 && (rawRecLen == 0 || rawRecLen == ^uint16(0)) {
				recLen = f.sb.blockSize
			}
			nameLen := uint16(data[off+6])
			fileType := data[off+7]
			if f.sb.featureIncompat&extFeatureIncompatFiletype == 0 {
				nameLen = binary.LittleEndian.Uint16(data[off+6 : off+8])
				fileType = 0
			}
			if recLen == 0 {
				return nil, fmt.Errorf("diskimage: directory inode %d has corrupt entry at offset %d (zero record length)", dirInodeNum, off)
			}
			if recLen < dirEntryHeaderSize || recLen%4 != 0 || off+int(recLen) > blockEnd {
				return nil, fmt.Errorf("diskimage: directory inode %d has corrupt entry at offset %d (invalid record length %d)", dirInodeNum, off, recLen)
			}
			nameEnd := off + dirEntryHeaderSize + int(nameLen)
			if nameLen > 255 || nameEnd > off+int(recLen) {
				return nil, fmt.Errorf("diskimage: directory inode %d has corrupt entry at offset %d (name overruns record)", dirInodeNum, off)
			}
			if entInode != 0 {
				name := string(data[off+dirEntryHeaderSize : nameEnd])
				materialise := name != "." && name != ".."
				if materialise {
					if err := validateEntryName(name); err != nil {
						return nil, fmt.Errorf("diskimage: directory inode %d: %w", dirInodeNum, err)
					}
				}
				childInode, err := f.readInode(entInode)
				if err != nil {
					if materialise && tolerateUnreadableLeaves && fileType >= 1 && fileType <= 7 && fileType != 2 {
						entries = append(entries, DirEntry{Name: name, Inode: entInode})
					} else {
						return nil, fmt.Errorf("diskimage: directory inode %d entry %q: %w", dirInodeNum, name, err)
					}
				} else {
					expectedType := inodeDirFileType(childInode.mode)
					if expectedType == 0xff || fileType > 7 || (fileType != 0 && fileType != expectedType) {
						return nil, fmt.Errorf("diskimage: directory inode %d entry %q has inconsistent file type %d for mode 0x%04X", dirInodeNum, name, fileType, childInode.mode)
					}
					if materialise {
						isDir := f.isDir(childInode)
						var size uint64
						if !isDir {
							size = uint64(childInode.sizeLo)
						}
						entries = append(entries, DirEntry{
							Name:  name,
							IsDir: isDir,
							Inode: entInode,
							Size:  size,
						})
					}
				}
			}
			off += int(recLen)
		}
		if off != blockEnd {
			return nil, fmt.Errorf("diskimage: directory inode %d has a truncated entry header at offset %d", dirInodeNum, off)
		}
	}
	return entries, nil
}

func inodeDirFileType(mode uint16) byte {
	switch mode & s_IFMT {
	case s_IFREG:
		return 1
	case s_IFDIR:
		return 2
	case s_IFCHR:
		return 3
	case s_IFBLK:
		return 4
	case s_IFIFO:
		return 5
	case s_IFSOCK:
		return 6
	case s_IFLNK:
		return 7
	default:
		return 0xff
	}
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
	if len(parts) > maxDirectoryDepth || uint64(len(parts)) > uint64(f.sb.inodesCount) {
		return 0, fmt.Errorf("diskimage: path exceeds directory traversal limit")
	}
	cur := uint32(rootInode)
	walked := ""
	visited := map[uint32]string{rootInode: "/"}
	var recordBudget uint64
	var byteBudget uint64
	for _, part := range parts {
		if err := validateEntryName(part); err != nil {
			return 0, fmt.Errorf("diskimage: resolving %q: %w", path, err)
		}
		entries, err := f.readDirEntriesBudget(cur, &recordBudget, &byteBudget)
		if err != nil {
			return 0, fmt.Errorf("diskimage: resolving %q: %w", path, err)
		}
		found := false
		for _, e := range entries {
			if e.Name == part {
				if e.IsDir {
					if previous, ok := visited[e.Inode]; ok {
						return 0, fmt.Errorf("diskimage: resolving %q reuses directory inode %d already visited at %q", path, e.Inode, previous)
					}
					visited[e.Inode] = walked + "/" + part
				}
				cur = e.Inode
				found = true
				break
			}
		}
		if !found {
			if walked == "" {
				walked = "/"
			}
			return 0, fmt.Errorf("%w: %q under %q (resolving %q)", ErrNotFound, part, walked, path)
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
	if in.mode&s_IFMT == s_IFLNK {
		linkNum := num
		target, err := f.readSymlinkData(num, in)
		if err != nil {
			return nil, fmt.Errorf("diskimage: reading file symlink %q (inode %d): %w", path, num, err)
		}
		targetPath, err := sameDirectorySymlinkTarget(path, string(target))
		if err != nil {
			return nil, fmt.Errorf("diskimage: reading file symlink %q (inode %d): %w", path, num, err)
		}
		num, err = f.resolve(targetPath)
		if err != nil {
			return nil, fmt.Errorf("diskimage: resolving file symlink %q (inode %d): %w", path, linkNum, err)
		}
		in, err = f.readInode(num)
		if err != nil {
			return nil, fmt.Errorf("diskimage: reading file symlink target %q (inode %d): %w", path, num, err)
		}
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

func sameDirectorySymlinkTarget(filePath, target string) (string, error) {
	if !strings.HasPrefix(target, "./") || strings.ContainsRune(target, '\x00') || path.IsAbs(target) {
		return "", fmt.Errorf("unsupported file symlink target %q", target)
	}
	cleanTarget := target[2:]
	if cleanTarget == "" || strings.Contains(cleanTarget, "/") {
		return "", fmt.Errorf("unsupported file symlink target %q", target)
	}
	if err := validateEntryName(cleanTarget); err != nil {
		return "", fmt.Errorf("unsupported file symlink target %q: %w", target, err)
	}
	parts := splitPath(filePath)
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid file symlink path %q", filePath)
	}
	return path.Join(path.Join(parts[:len(parts)-1]...), cleanTarget), nil
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
		return fmt.Errorf("diskimage: extraction destination is not a real directory: %q", destDir)
	}
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return err
	}
	defer root.Close()
	state := &extractState{
		visited:      map[uint32]string{rootInode: "/"},
		regularFiles: make(map[uint32]string),
	}
	return f.extractDir("", "", rootInode, root, state, 0)
}

type extractState struct {
	visited        map[uint32]string
	regularFiles   map[uint32]string
	entries        uint64
	records        uint64
	directoryBytes uint64
}

func (f *FS) extractDir(relPath, destPath string, dirInodeNum uint32, root *os.Root, state *extractState, depth uint64) error {
	if depth > maxDirectoryDepth {
		return fmt.Errorf("diskimage: directory tree exceeds depth limit %d", maxDirectoryDepth)
	}
	if state.regularFiles == nil {
		state.regularFiles = make(map[uint32]string)
	}
	entries, err := f.readDirEntriesBudgetMode(dirInodeNum, &state.records, &state.directoryBytes, true)
	if err != nil {
		return err
	}
	totalEntries, ok := checkedAdd(state.entries, uint64(len(entries)))
	if !ok || totalEntries > maxDirectoryEntries {
		return fmt.Errorf("diskimage: directory tree exceeds entry limit %d", maxDirectoryEntries)
	}
	state.entries = totalEntries
	for _, e := range entries {
		if err := validateEntryName(e.Name); err != nil {
			return err
		}
		childRel := e.Name
		if relPath != "" {
			childRel = relPath + "/" + e.Name
		}
		target := filepath.Join(destPath, e.Name)
		if e.IsDir {
			if previous, ok := state.visited[e.Inode]; ok {
				return fmt.Errorf("diskimage: directory %q reuses inode %d already visited at %q", childRel, e.Inode, previous)
			}
			state.visited[e.Inode] = childRel
			if err := root.Mkdir(target, 0o755); err != nil {
				return fmt.Errorf("diskimage: creating directory %q: %w", childRel, err)
			}
			if err := f.extractDir(childRel, target, e.Inode, root, state, depth+1); err != nil {
				return err
			}
			continue
		}
		if previous, ok := state.regularFiles[e.Inode]; ok {
			if err := root.Link(previous, target); err != nil {
				return fmt.Errorf("diskimage: linking %q to %q: %w", childRel, previous, err)
			}
			continue
		}
		in, err := f.readInode(e.Inode)
		if err != nil {
			continue
		}
		switch in.mode & s_IFMT {
		case s_IFREG:
			data, err := f.readInodeData(e.Inode, in)
			if err != nil {
				if errors.Is(err, errCannotMaterialise) {
					return fmt.Errorf("diskimage: reading file %q (inode %d): %w", childRel, e.Inode, err)
				}
				continue
			}
			out, err := root.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
			if err != nil {
				return fmt.Errorf("diskimage: creating %q: %w", childRel, err)
			}
			if _, err := out.Write(data); err != nil {
				_ = out.Close()
				_ = root.Remove(target)
				return fmt.Errorf("diskimage: writing %q: %w", childRel, err)
			}
			if err := out.Close(); err != nil {
				_ = root.Remove(target)
				return err
			}
			state.regularFiles[e.Inode] = target
		case s_IFLNK:
			targetBytes, err := f.readSymlinkData(e.Inode, in)
			if err != nil {
				continue
			}
			linkTarget, err := safeExtractSymlinkTarget(target, string(targetBytes))
			if err != nil {
				return err
			}
			if err := root.Symlink(linkTarget, target); err != nil {
				return fmt.Errorf("diskimage: creating symlink %q: %w", childRel, err)
			}
		default:
			// Device nodes and FIFOs are intentionally not materialised.
		}
	}
	return nil
}

func validateEntryName(name string) error {
	if name == "" || len(name) > 255 || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("unsafe filesystem entry name %q", name)
	}
	return nil
}

func safeExtractSymlinkTarget(linkName, linkTarget string) (string, error) {
	if linkTarget == "" || strings.ContainsRune(linkTarget, '\x00') {
		return "", fmt.Errorf("diskimage: symlink %q has an invalid target", linkName)
	}
	linkName = filepath.ToSlash(linkName)
	target := strings.ReplaceAll(linkTarget, `\`, "/")
	if path.IsAbs(target) {
		target = strings.TrimPrefix(path.Clean(target), "/")
	} else {
		target = path.Clean(path.Join(path.Dir(linkName), target))
	}
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", fmt.Errorf("diskimage: symlink %q escapes destination: %q", linkName, linkTarget)
	}
	return filepath.Rel(filepath.FromSlash(path.Dir(linkName)), filepath.FromSlash(target))
}

// readSymlinkData returns a symlink's content bytes. Fast targets are stored
// inline in the i_block area; slow ones use the inode's block map.
func (f *FS) readSymlinkData(num uint32, in *inode) ([]byte, error) {
	if in.sizeLo > maxSymlinkSize {
		return nil, fmt.Errorf("diskimage: symlink inode %d size %d exceeds limit %d", num, in.sizeLo, maxSymlinkSize)
	}
	raw := in.blockRaw[:]
	if uint64(in.sizeLo) <= uint64(len(raw)) {
		return raw[:in.sizeLo], nil
	}
	return f.readInodeData(num, in)
}
