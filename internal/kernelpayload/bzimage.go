package kernelpayload

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/binary"
	"io"
)

// Bishop Fox and Rapid7 describe the FAZ/FMG kernel's repeating XOR key:
// https://bishopfox.com/blog/a-look-at-fortijump-cve-2024-47575
// https://www.rapid7.com/blog/post/ra-cve-2024-47575-analysis/
// Recover the four stack-stored immediates rather than embedding build keys.
// Byte zero has a separate XOR; gzip integrity and ELF bounds validate it.
func extractProtectedBZImage(image []byte, maxExpanded int64) ([]byte, int) {
	if len(image) < 0x250 || string(image[0x202:0x206]) != "HdrS" || binary.LittleEndian.Uint16(image[0x206:]) < 0x20b {
		return nil, 0
	}
	setup := uint64(image[0x1f1])
	if setup == 0 {
		setup = 4
	}
	start := (setup+1)*512 + uint64(binary.LittleEndian.Uint32(image[0x248:]))
	n := uint64(binary.LittleEndian.Uint32(image[0x24c:]))
	if n < 18 || start > uint64(len(image)) || n > uint64(len(image))-start {
		return nil, 0
	}
	end := int(start + n)
	for pos := end; pos+58 <= len(image); pos++ {
		key, ok := bzImageXORKey(image[pos:])
		if !ok || image[int(start)+1]^key[1] != 0x8b || image[int(start)+2]^key[2] != 8 {
			continue
		}
		decoded := make([]byte, int(n))
		decoded[0] = 0x1f
		for i := 1; i < len(decoded); i++ {
			decoded[i] = image[int(start)+i] ^ key[i&31]
		}
		compressed := bytes.NewReader(decoded)
		gz, err := gzip.NewReader(compressed)
		if err != nil {
			continue
		}
		gz.Multistream(false)
		payload, err := io.ReadAll(io.LimitReader(gz, maxExpanded+1))
		_ = gz.Close()
		if err == nil && int64(len(payload)) <= maxExpanded && len(payload) > minKernelPayloadSize && compressed.Len() == 0 && validKernelELF(payload) {
			return payload, int(start)
		}
	}
	return nil, 0
}

func bzImageXORKey(stub []byte) (key [32]byte, ok bool) {
	pos, base := 0, -1
	for i := 0; i < 4; i++ {
		if len(stub)-pos < 14 || stub[pos] != 0x48 || stub[pos+1] != 0xb8 {
			return key, false
		}
		copy(key[i*8:], stub[pos+2:pos+10])
		pos += 10
		// Newer stubs load the payload length between the first immediate
		// and its stack store (mov disp32(%rip), %r8d).
		if i == 0 && len(stub)-pos >= 7 && bytes.Equal(stub[pos:pos+3], []byte{0x44, 0x8b, 0x05}) {
			pos += 7
		}
		if len(stub)-pos < 4 {
			return key, false
		}
		var slot int
		switch {
		case bytes.Equal(stub[pos:pos+4], []byte{0x48, 0x89, 0x04, 0x24}):
			slot = 0
			pos += 4
		case len(stub)-pos >= 5 && bytes.Equal(stub[pos:pos+4], []byte{0x48, 0x89, 0x44, 0x24}):
			slot = int(int8(stub[pos+4]))
			pos += 5
		default:
			return key, false
		}
		if i == 0 {
			base = slot
		}
		if slot != base+i*8 {
			return key, false
		}
	}
	return key, true
}

func validKernelELF(payload []byte) bool {
	f, err := elf.NewFile(bytes.NewReader(payload))
	if err != nil {
		return false
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_X86_64 || f.Type != elf.ET_EXEC {
		return false
	}
	executable := false
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Off > uint64(len(payload)) || p.Filesz > uint64(len(payload))-p.Off || p.Filesz > p.Memsz {
			return false
		}
		if p.Filesz > 0 && p.Flags&elf.PF_X != 0 {
			executable = true
		}
	}
	return executable
}
