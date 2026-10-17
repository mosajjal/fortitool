package kernelpayload

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func testELF() []byte {
	b := make([]byte, minKernelPayloadSize+128)
	copy(b, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	binary.LittleEndian.PutUint32(b[68:], 5)
	binary.LittleEndian.PutUint64(b[96:], uint64(len(b)))
	binary.LittleEndian.PutUint64(b[104:], uint64(len(b)))
	return b
}

func testProtectedBZImage(t *testing.T, payload []byte, stack byte, loadLength bool) ([]byte, int) {
	t.Helper()
	compressed := gzipBytes(t, payload)
	key := []byte("synthetic 32-byte XOR test key!!!")
	const off = 0x810
	b := make([]byte, off)
	b[0x1f1] = 3
	copy(b[0x202:], "HdrS")
	binary.LittleEndian.PutUint16(b[0x206:], 0x20b)
	binary.LittleEndian.PutUint32(b[0x248:], off-0x800)
	binary.LittleEndian.PutUint32(b[0x24c:], uint32(len(compressed)))
	for i, v := range compressed {
		k := key[i&31]
		if i == 0 {
			k = 0x53
		}
		b = append(b, v^k)
	}
	b = append(b, bytes.Repeat([]byte{0x90}, 17)...)
	for i := 0; i < 4; i++ {
		b = append(b, 0x48, 0xb8)
		b = append(b, key[i*8:i*8+8]...)
		if i == 0 && loadLength {
			b = append(b, 0x44, 0x8b, 0x05, 0x12, 0, 0, 0)
		}
		if stack+byte(i*8) == 0 {
			b = append(b, 0x48, 0x89, 0x04, 0x24)
		} else {
			b = append(b, 0x48, 0x89, 0x44, 0x24, stack+byte(i*8))
		}
	}
	return b, off
}

func TestExtractProtectedBZImage(t *testing.T) {
	for _, stack := range []byte{0, 0x30, 0x60} {
		for _, load := range []bool{false, true} {
			want := testELF()
			b, off := testProtectedBZImage(t, want, stack, load)
			got, gotOff, err := Extract(b)
			if err != nil || gotOff != off || !bytes.Equal(got, want) {
				t.Fatalf("stack=%d load=%v: offset=%d err=%v", stack, load, gotOff, err)
			}
		}
	}
}

func TestProtectedBZImageRejectsInvalidCandidates(t *testing.T) {
	for _, kind := range []string{"key", "crc", "length", "header", "not-elf", "truncated-stub", "limit"} {
		t.Run(kind, func(t *testing.T) {
			payload := testELF()
			if kind == "not-elf" {
				payload[0] = 0
			}
			b, off := testProtectedBZImage(t, payload, 0x30, false)
			n := int(binary.LittleEndian.Uint32(b[0x24c:]))
			limit := int64(maxKernelPayloadSize)
			switch kind {
			case "key":
				b[len(b)-10] ^= 1
			case "crc":
				b[off+n-8] ^= 1
			case "length":
				binary.LittleEndian.PutUint32(b[0x24c:], uint32(len(b)))
			case "header":
				b[0x202] = 0
			case "truncated-stub":
				b = b[:len(b)-1]
			case "limit":
				limit = int64(len(payload) - 1)
			}
			if _, _, err := extract(b, limit); err == nil {
				t.Fatal("invalid protected kernel accepted")
			}
		})
	}
}
