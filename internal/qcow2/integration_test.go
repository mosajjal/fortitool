package qcow2

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/mosajjal/fortitool/internal/diskimage"
)

// TestDiskimageOverQCow2 wires this package into the unpack pipeline's
// volume-discovery path: a partitioned guest disk (MBR + ext filesystem
// holding flatkc/rootfs.gz -- the FortiGate-VM layout) packed as qcow2,
// discovered and read through diskimage.FindFilesystems.
func TestDiskimageOverQCow2(t *testing.T) {
	const bs = 1024

	// --- minimal ext image: superblock, GDT, inode table, root dir, 2 files
	ext := make([]byte, 16*bs)
	block := func(n int) []byte { return ext[n*bs : (n+1)*bs] }
	le32 := binary.LittleEndian.PutUint32
	le16 := binary.LittleEndian.PutUint16

	sb := block(1)
	le32(sb[0:4], 8)
	le32(sb[4:8], 16)
	le32(sb[20:24], 1)
	le32(sb[24:28], 0)
	le32(sb[32:36], 16)
	le32(sb[40:44], 8)
	le32(sb[76:80], 1)
	le16(sb[56:58], 0xEF53)
	le16(sb[88:90], 128)
	le32(sb[96:100], 0x0002) // EXT2_FEATURE_INCOMPAT_FILETYPE
	le32(block(2)[4:8], 7)   // bg_inode_bitmap
	le32(block(2)[8:12], 3)  // bg_inode_table
	block(7)[0] = 0x0f

	writeInode := func(num uint32, mode uint16, size uint32, dataBlock uint32) {
		raw := block(3)[(num-1)*128 : num*128]
		le16(raw[0:2], mode)
		le32(raw[4:8], size)
		le32(raw[40:44], dataBlock)
	}
	writeInode(2, 0o040000|0o755, bs, 4) // root dir
	writeInode(3, 0o100000|0o644, 4, 5)  // flatkc
	writeInode(4, 0o100000|0o644, 6, 6)  // rootfs.gz

	rootDir := block(4)
	copy(rootDir[0:], []byte{
		2, 0, 0, 0, 12, 0, 1, 2, '.', '.', 0, 0,
	})
	ent := func(off int, ino uint32, name string, final bool) int {
		recLen := (8 + len(name) + 3) &^ 3
		if final {
			recLen = len(rootDir) - off
		}
		le32(rootDir[off:off+4], ino)
		le16(rootDir[off+4:off+6], uint16(recLen))
		rootDir[off+6] = byte(len(name))
		rootDir[off+7] = 1
		copy(rootDir[off+8:], name)
		return off + recLen
	}
	off := ent(12, 3, "flatkc", false)
	ent(off, 4, "rootfs.gz", true)
	copy(block(5), "KERN")
	copy(block(6), "ROOTFS")

	// --- raw guest disk: MBR sector + ext at sector 1
	disk := make([]byte, 512+len(ext))
	copy(disk[512:], ext)
	disk[510], disk[511] = 0x55, 0xAA
	pe := disk[446 : 446+16]
	pe[4] = 0x83
	le32(pe[8:12], 1)
	le32(pe[12:16], uint32(len(disk)-512)/512)

	// --- pack the whole disk as qcow2 (single cluster worth of content)
	img := buildImage(t, 1<<testClusterBits, map[uint64][]byte{0: disk})

	rd, err := Open(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("qcow2.Open: %v", err)
	}
	fss := diskimage.FindFilesystems(rd, rd.Size())
	if len(fss) == 0 {
		t.Fatal("FindFilesystems found no ext volume inside the qcow2 disk")
	}
	got, err := fss[0].ReadFile("flatkc")
	if err != nil || string(got) != "KERN" {
		t.Fatalf("flatkc = %q, %v", got, err)
	}
	got, err = fss[0].ReadFile("rootfs.gz")
	if err != nil || string(got) != "ROOTFS" {
		t.Fatalf("rootfs.gz = %q, %v", got, err)
	}
}
