package archive

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

type testXZLayout struct {
	blockCRC   int
	checkStart int
	indexCRC   int
	footerCRC  int
}

func TestFortinetXZRepairsOnlyFourChecksumFields(t *testing.T) {
	plain := []byte("synthetic redistributable payload")
	standard := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.SHA256}, plain)
	modified, layout := addFortinetXZPlaceholders(t, standard)
	before := append([]byte(nil), modified...)

	r, err := fortinetXZReader(modified)
	if err != nil {
		t.Fatal(err)
	}
	repaired, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repaired, standard) {
		t.Fatal("repaired stream does not match the standards-compliant source")
	}
	if !bytes.Equal(modified, before) {
		t.Fatal("repair modified the caller's input")
	}

	allowed := make([]bool, len(modified))
	for _, offset := range []int{8, layout.blockCRC, layout.indexCRC, layout.footerCRC} {
		for i := offset; i < offset+4; i++ {
			allowed[i] = true
		}
	}
	for i := range modified {
		if modified[i] != repaired[i] && !allowed[i] {
			t.Fatalf("repair changed byte %d outside a checksum field", i)
		}
	}
}

func TestFortinetXZChecksumPatchesCrossReadBoundaries(t *testing.T) {
	standard := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.SHA256}, []byte("chunked reader payload"))
	modified, _ := addFortinetXZPlaceholders(t, standard)

	for _, chunkSize := range []int{1, 2, 3, 5, 7} {
		r, err := fortinetXZReader(modified)
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		buf := make([]byte, chunkSize)
		for {
			n, readErr := r.Read(buf)
			got = append(got, buf[:n]...)
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
		}
		if !bytes.Equal(got, standard) {
			t.Fatalf("%d-byte reads did not reconstruct the standard stream", chunkSize)
		}
	}
}

func TestExtractFortinetXZPlaceholderTar(t *testing.T) {
	tarData := buildTar(t, []testFile{{"./bin/init", "#!/bin/fake\n"}})
	standard := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.SHA256}, tarData)
	modified, _ := addFortinetXZPlaceholders(t, standard)

	dest := t.TempDir()
	if err := ExtractXZTar(modified, dest); err != nil {
		t.Fatalf("ExtractXZTar: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "bin", "init"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "#!/bin/fake\n" {
		t.Fatalf("payload = %q", got)
	}
}

func TestStandardXZPassesThroughUnchanged(t *testing.T) {
	plain := []byte("standards-compliant payload")
	for _, tc := range []struct {
		name   string
		config xz.WriterConfig
	}{
		{name: "CRC64", config: xz.WriterConfig{CheckSum: xz.CRC64}},
		{name: "SHA256", config: xz.WriterConfig{CheckSum: xz.SHA256}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			standard := buildTestXZ(t, tc.config, plain)
			r, err := fortinetXZReader(standard)
			if err != nil {
				t.Fatal(err)
			}
			gotCompressed, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotCompressed, standard) {
				t.Fatal("standard XZ stream was changed")
			}
			gotPlain, err := XZDecompress(standard)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotPlain, plain) {
				t.Fatalf("payload = %q", gotPlain)
			}
		})
	}
}

func TestStandardXZMultipleStreamsAndPaddingRemainSupported(t *testing.T) {
	first := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.CRC64}, []byte("first"))
	second := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.SHA256}, []byte("second"))
	stream := append(append(append([]byte(nil), first...), 0, 0, 0, 0), second...)

	got, err := XZDecompress(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "firstsecond" {
		t.Fatalf("payload = %q", got)
	}
}

func TestFortinetXZPlaceholderRejectsNearMisses(t *testing.T) {
	baseStandard := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.SHA256}, []byte("near-miss payload"))
	baseModified, layout := addFortinetXZPlaceholders(t, baseStandard)

	tests := []struct {
		name string
		data func() []byte
	}{
		{
			name: "stream header placeholder",
			data: func() []byte {
				data := append([]byte(nil), baseModified...)
				data[8] ^= 1
				return data
			},
		},
		{
			name: "block header placeholder",
			data: func() []byte {
				data := append([]byte(nil), baseModified...)
				data[layout.blockCRC] ^= 1
				return data
			},
		},
		{
			name: "index placeholder",
			data: func() []byte {
				data := append([]byte(nil), baseModified...)
				data[layout.indexCRC] ^= 1
				return data
			},
		},
		{
			name: "footer placeholder",
			data: func() []byte {
				data := append([]byte(nil), baseModified...)
				data[layout.footerCRC] ^= 1
				return data
			},
		},
		{
			name: "CRC64 check",
			data: func() []byte {
				standard := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.CRC64}, []byte("near-miss payload"))
				modified, _ := addFortinetXZPlaceholders(t, standard)
				return modified
			},
		},
		{
			name: "multiple blocks",
			data: func() []byte {
				standard := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.SHA256, BlockSize: 8}, []byte("payload split into several blocks"))
				modified, _ := addFortinetXZPlaceholders(t, standard)
				return modified
			},
		},
		{
			name: "multiple streams",
			data: func() []byte {
				second := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.SHA256}, []byte("second stream"))
				return append(append([]byte(nil), baseModified...), second...)
			},
		},
		{
			name: "stream padding",
			data: func() []byte {
				return append(append([]byte(nil), baseModified...), 0, 0, 0, 0)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := XZDecompress(tc.data()); err == nil {
				t.Fatal("expected checksum-placeholder near-miss to fail")
			}
		})
	}
}

func TestExtractFortinetXZPlaceholderRejectsCorruptSHA256Check(t *testing.T) {
	tarData := buildTar(t, []testFile{{"file", "complete tar payload"}})
	// Keep compressed data after the tar end markers so this regression
	// specifically requires ExtractXZTar's decoder drain to reach the check.
	tarData = append(tarData, make([]byte, 1<<20)...)
	standard := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.SHA256}, tarData)
	modified, layout := addFortinetXZPlaceholders(t, standard)
	modified[layout.checkStart] ^= 1

	err := ExtractXZTar(modified, filepath.Join(t.TempDir(), "output"))
	if err == nil {
		t.Fatal("expected a corrupt SHA-256 block check to fail")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("error = %v, want a checksum failure", err)
	}
}

func TestExtractXZTarRejectsCorruptFooterChecksum(t *testing.T) {
	tarData := buildTar(t, []testFile{{"file", "complete tar payload"}})
	tarData = append(tarData, make([]byte, 1<<20)...)
	standard := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.CRC64}, tarData)
	standard[len(standard)-xzStreamFooterSize] ^= 1

	if err := ExtractXZTar(standard, filepath.Join(t.TempDir(), "output")); err == nil {
		t.Fatal("expected a corrupt stream-footer checksum to fail")
	}
}

func TestFortinetXZPlaceholderRejectsEveryTruncation(t *testing.T) {
	standard := buildTestXZ(t, xz.WriterConfig{CheckSum: xz.SHA256}, []byte("truncation payload"))
	modified, _ := addFortinetXZPlaceholders(t, standard)

	for cut := 0; cut < len(modified); cut++ {
		if _, err := XZDecompress(modified[:cut]); err == nil {
			t.Fatalf("truncation at byte %d succeeded", cut)
		}
	}
}

func buildTestXZ(t *testing.T, config xz.WriterConfig, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	xw, err := config.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func addFortinetXZPlaceholders(t *testing.T, standard []byte) ([]byte, testXZLayout) {
	t.Helper()
	if len(standard) < xzStreamHeaderSize+xzStreamFooterSize {
		t.Fatal("short synthetic XZ stream")
	}
	footerCRC := len(standard) - xzStreamFooterSize
	footer := standard[footerCRC:]
	if footer[10] != 'Y' || footer[11] != 'Z' {
		t.Fatal("synthetic XZ footer is missing")
	}
	indexSize := (uint64(binary.LittleEndian.Uint32(footer[4:8])) + 1) * 4
	if indexSize > uint64(len(standard)-xzStreamFooterSize) {
		t.Fatal("invalid synthetic XZ index size")
	}
	indexStart := len(standard) - xzStreamFooterSize - int(indexSize)
	indexCRC := len(standard) - xzStreamFooterSize - 4
	blockHeaderSize := (int(standard[xzStreamHeaderSize]) + 1) * 4
	blockCRC := xzStreamHeaderSize + blockHeaderSize - 4

	indexBody := standard[indexStart:indexCRC]
	pos := 1
	if _, err := readTestXZVLI(indexBody, &pos); err != nil {
		t.Fatal(err)
	}
	unpaddedSize, err := readTestXZVLI(indexBody, &pos)
	if err != nil {
		t.Fatal(err)
	}
	if unpaddedSize < xzSHA256CheckSize {
		t.Fatal("synthetic XZ block is too short")
	}
	paddedSize := (unpaddedSize + 3) &^ uint64(3)
	checkStart := xzStreamHeaderSize + int(paddedSize) - xzSHA256CheckSize

	modified := append([]byte(nil), standard...)
	binary.LittleEndian.PutUint32(modified[8:xzStreamHeaderSize], fortinetStreamHeaderCRC)
	binary.LittleEndian.PutUint32(modified[blockCRC:blockCRC+4], fortinetOtherCRC)
	binary.LittleEndian.PutUint32(modified[indexCRC:indexCRC+4], fortinetOtherCRC)
	binary.LittleEndian.PutUint32(modified[footerCRC:footerCRC+4], fortinetOtherCRC)
	return modified, testXZLayout{
		blockCRC:   blockCRC,
		checkStart: checkStart,
		indexCRC:   indexCRC,
		footerCRC:  footerCRC,
	}
}

func readTestXZVLI(data []byte, pos *int) (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 63 && *pos < len(data); shift += 7 {
		b := data[*pos]
		(*pos)++
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}
