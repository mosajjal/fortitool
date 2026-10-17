package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mosajjal/fortitool/internal/diskimage"
	"github.com/ulikunitz/xz"
)

func syntheticVMImage(t *testing.T, rootfs []byte) []byte {
	return syntheticVMImageWithKernel(t, []byte("synthetic flatkc"), rootfs)
}

func syntheticVMImageWithKernel(t *testing.T, kernel, rootfs []byte) []byte {
	t.Helper()
	ext, err := gunzipOuter(syntheticDecryptImageWithMembers(t, kernel, rootfs))
	if err != nil {
		t.Fatal(err)
	}
	clear(ext[:512])
	off := bytes.Index(ext, []byte("flatkc"))
	if off < 0 {
		t.Fatal("fixture has no flatkc entry")
	}
	ext[off-2] = byte(len("vmlinuz"))
	copy(ext[off:], "vmlinuz")
	return buildQCOW2Disk(buildPartitionedDisk(ext))
}

func TestInspectCleartextQCOW2RetainsL1Identity(t *testing.T) {
	ext, err := gunzipOuter(syntheticDecryptImage(t, syntheticNewcRootfs(t, true)))
	if err != nil {
		t.Fatal(err)
	}
	disk := buildQCOW2Disk(buildPartitionedDisk(ext))
	for _, wrapped := range []bool{false, true} {
		image := disk
		if wrapped {
			image = gzipBytes(t, disk)
		}
		input := filepath.Join(t.TempDir(), "firmware.out")
		if err := os.WriteFile(input, image, 0600); err != nil {
			t.Fatal(err)
		}
		report, err := captureStdout(t, func() error { return cmdInspect(context.Background(), []string{input}) })
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"l1-state: cleartext\n", "firmware-identity: SYNTH-v0.0.0-FW-build0000-test\n", "vmlinuz: not checked\n", "status: complete\n"} {
			if !strings.Contains(report, want) {
				t.Fatalf("gzip=%v: missing %q in %s", wrapped, want, report)
			}
		}
	}
}

func TestFAZFMGProtectedImage(t *testing.T) {
	newc, err := gunzipOuter(syntheticNewcRootfs(t, true))
	if err != nil {
		t.Fatal(err)
	}
	plain := xzBytes(t, newc)
	kernel := make([]byte, 1_000_128)
	copy(kernel, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(kernel[16:], 2)
	binary.LittleEndian.PutUint16(kernel[18:], 62)
	binary.LittleEndian.PutUint32(kernel[20:], 1)
	binary.LittleEndian.PutUint64(kernel[32:], 64)
	binary.LittleEndian.PutUint16(kernel[52:], 64)
	binary.LittleEndian.PutUint16(kernel[54:], 56)
	binary.LittleEndian.PutUint16(kernel[56:], 1)
	binary.LittleEndian.PutUint32(kernel[64:], 1)
	binary.LittleEndian.PutUint32(kernel[68:], 5)
	binary.LittleEndian.PutUint64(kernel[96:], uint64(len(kernel)))
	binary.LittleEndian.PutUint64(kernel[104:], uint64(len(kernel)))
	copy(kernel[128:], "test AES key!!!!test AES IV!!!!!")
	block, err := aes.NewCipher(kernel[128:144])
	if err != nil {
		t.Fatal(err)
	}
	rootfs := make([]byte, len(plain))
	cipher.NewCTR(block, kernel[144:160]).XORKeyStream(rootfs, plain)
	digest := sha256.Sum256(plain)
	rootfs = append(rootfs, digest[:]...)
	compressed := gzipBytes(t, kernel)
	vmlinuz := make([]byte, 0x800)
	vmlinuz[0x1f1] = 3
	copy(vmlinuz[0x202:], "HdrS")
	binary.LittleEndian.PutUint16(vmlinuz[0x206:], 0x20b)
	binary.LittleEndian.PutUint32(vmlinuz[0x24c:], uint32(len(compressed)))
	key := []byte("independent synthetic XOR key!!!")
	for i, b := range compressed {
		k := key[i&31]
		if i == 0 {
			k = 0xa4
		}
		vmlinuz = append(vmlinuz, b^k)
	}
	for i := 0; i < 4; i++ {
		vmlinuz = append(vmlinuz, 0x48, 0xb8)
		vmlinuz = append(vmlinuz, key[i*8:i*8+8]...)
		vmlinuz = append(vmlinuz, 0x48, 0x89, 0x44, 0x24, byte(0x30+i*8))
	}
	for _, corrupt := range []bool{false, true} {
		dir := t.TempDir()
		input, output := filepath.Join(dir, "input.zip"), filepath.Join(dir, "output")
		if corrupt {
			rootfs[len(rootfs)-1] ^= 1
		}
		if err := os.WriteFile(input, zipVMImage(t, syntheticVMImageWithKernel(t, vmlinuz, rootfs)), 0600); err != nil {
			t.Fatal(err)
		}
		report, err := captureStdout(t, func() error { return cmdInspect(context.Background(), []string{input}) })
		if err != nil {
			t.Fatal(err)
		}
		_, err = captureStdout(t, func() error { return cmdDecrypt(context.Background(), []string{"-o", output, input}) })
		if corrupt {
			if err == nil || !strings.Contains(report, "status: partial\n") {
				t.Fatal("corrupt digest accepted")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("failed decrypt published output")
			}
			continue
		}
		if err != nil || !strings.Contains(report, "rootfs-body-cipher: aes-128-ctr\n") || !strings.Contains(report, "status: complete\n") {
			t.Fatalf("err=%v report=%s", err, report)
		}
		got, err := os.ReadFile(filepath.Join(output, "rootfs", "bin", "init"))
		if err != nil || string(got) != "synthetic init" {
			t.Fatalf("init=%q err=%v", got, err)
		}
	}
}

func zipVMImage(t *testing.T, image []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	w, err := zw.Create("firmware.qcow2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(image); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func xzBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := xz.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestFAZFMGInspectAndDecrypt(t *testing.T) {
	newc, err := gunzipOuter(syntheticNewcRootfs(t, true))
	if err != nil {
		t.Fatal(err)
	}
	for _, container := range []string{"gzip", "xz"} {
		for _, wrapper := range []string{"qcow2", "zip"} {
			t.Run(container+"/"+wrapper, func(t *testing.T) {
				rootfs := gzipBytes(t, newc)
				if container == "xz" {
					rootfs = xzBytes(t, newc)
				}
				image := syntheticVMImage(t, rootfs)
				if wrapper == "zip" {
					image = zipVMImage(t, image)
				}
				dir := t.TempDir()
				input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
				if err := os.WriteFile(input, image, 0600); err != nil {
					t.Fatal(err)
				}
				report, err := captureStdout(t, func() error { return cmdInspect(context.Background(), []string{input}) })
				if err != nil {
					t.Fatal(err)
				}
				for _, want := range []string{"l1-state: not applicable\n", "vmlinuz: present (16 bytes)\n", "rootfs-container: " + container + "/newc\n", "status: complete\n"} {
					if !strings.Contains(report, want) {
						t.Fatalf("missing %q in %s", want, report)
					}
				}
				_, err = captureStdout(t, func() error { return cmdDecrypt(context.Background(), []string{"-o", output, input}) })
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(filepath.Join(output, "rootfs", "bin", "init"))
				if err != nil || string(got) != "synthetic init" {
					t.Fatalf("init=%q err=%v", got, err)
				}
				if _, err := os.Stat(filepath.Join(output, "vmlinuz")); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(output, "flatkc")); !os.IsNotExist(err) {
					t.Fatalf("kernel was renamed: %v", err)
				}
			})
		}
	}
}

func TestFAZFMGUnsupportedRootfsDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	if err := os.WriteFile(input, zipVMImage(t, syntheticVMImage(t, []byte("unknown protected rootfs"))), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := captureStdout(t, func() error { return cmdInspect(context.Background(), []string{input}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report, "unsupported-stage: rootfs-crypto\n") {
		t.Fatal(report)
	}
	_, err = captureStdout(t, func() error { return cmdDecrypt(context.Background(), []string{"-o", output, input}) })
	if err == nil {
		t.Fatal("unsupported rootfs accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "input" {
		t.Fatalf("failed decrypt left output: %v", entries)
	}
}

func TestXZNewcRejectsTruncationAndInvalidArchive(t *testing.T) {
	valid, err := gunzipOuter(syntheticNewcRootfs(t, true))
	if err != nil {
		t.Fatal(err)
	}
	truncated := xzBytes(t, valid)
	truncated = truncated[:len(truncated)-4]
	for name, data := range map[string][]byte{"truncated XZ": truncated, "missing CPIO trailer": xzBytes(t, valid[:len(valid)-124]), "nonzero CPIO tail": xzBytes(t, append(valid, 1))} {
		t.Run(name, func(t *testing.T) {
			if _, err := classifyRootfsPayload(data); err == nil {
				t.Fatal("invalid payload classified")
			}
			if err := extractRootfsPayload(data, filepath.Join(t.TempDir(), "rootfs")); err == nil {
				t.Fatal("invalid payload extracted")
			}
		})
	}
}

func TestFAZFMGBootOnlyPreservesEncodedPayload(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	payload := []byte("unknown protected rootfs")
	if err := os.WriteFile(input, zipVMImage(t, syntheticVMImage(t, payload)), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := captureStdout(t, func() error { return cmdDecrypt(context.Background(), []string{"--boot-only", "-o", output, input}) })
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(output, "rootfs.gz"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload=%q err=%v", got, err)
	}
	if !strings.Contains(report, "rootfs was not decrypted or unpacked") {
		t.Fatal(report)
	}
	if _, err := os.Stat(filepath.Join(output, "rootfs")); !os.IsNotExist(err) {
		t.Fatalf("unexpected rootfs tree: %v", err)
	}
	_, err = captureStdout(t, func() error { return cmdDecrypt(context.Background(), []string{"--boot-only", "-o", output, input}) })
	if err == nil {
		t.Fatal("overwrote existing destination")
	}
	again, err := os.ReadFile(filepath.Join(output, "rootfs.gz"))
	if err != nil || !bytes.Equal(again, payload) {
		t.Fatal("existing payload changed")
	}
}

func tarBytes(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for name, data := range entries {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestFAZFMGPreservesDistinctArchiveLayers(t *testing.T) {
	nested := xzBytes(t, tarBytes(t, map[string][]byte{"bin/init": []byte("application")}))
	root := gzipBytes(t, tarBytes(t, map[string][]byte{"bin/init": []byte("bootstrap"), "bin.tar.xz": nested, "lib.tar.xz": xzBytes(t, tarBytes(t, map[string][]byte{"lib/libc.so": []byte("library")}))}))
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	if err := os.WriteFile(input, zipVMImage(t, syntheticVMImage(t, root)), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := captureStdout(t, func() error { return cmdDecrypt(context.Background(), []string{"-o", output, input}) })
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"rootfs/bin/init": "bootstrap", "layers/rootfs/bin.tar.xz/bin/init": "application", "layers/rootfs/lib.tar.xz/lib/libc.so": "library"} {
		got, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(name)))
		if err != nil || string(got) != want {
			t.Fatalf("%s=%q err=%v", name, got, err)
		}
	}
	// FortiGate's established merge contract must continue rejecting collisions.
	fgtInput := filepath.Join(dir, "fgt")
	if err := os.WriteFile(fgtInput, syntheticDecryptImage(t, root), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = captureStdout(t, func() error {
		return cmdDecrypt(context.Background(), []string{"-o", filepath.Join(dir, "fgt-output"), fgtInput})
	})
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("FortiGate collision error=%v", err)
	}
}

func TestZIPDiskRejectsAmbiguousUnsafeAndCorruptPackages(t *testing.T) {
	disk := syntheticVMImage(t, syntheticNewcRootfs(t, true))
	makeZip := func(names []string, mode os.FileMode, data []byte) []byte {
		var out bytes.Buffer
		w := zip.NewWriter(&out)
		for _, name := range names {
			h := &zip.FileHeader{Name: name, Method: zip.Store}
			h.SetMode(mode)
			f, err := w.CreateHeader(h)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	corrupt := makeZip([]string{"disk"}, 0600, disk)
	off := bytes.Index(corrupt, []byte("QFI\xfb"))
	corrupt[off+100] ^= 1
	encrypted := makeZip([]string{"disk"}, 0600, disk)
	central := bytes.Index(encrypted, []byte("PK\x01\x02"))
	binary.LittleEndian.PutUint16(encrypted[central+8:central+10], 1)
	truncated := makeZip([]string{"disk"}, 0600, disk)
	truncated = truncated[:len(truncated)-16]
	for name, data := range map[string][]byte{
		"empty": makeZip(nil, 0600, nil), "multiple": makeZip([]string{"a", "b"}, 0600, disk), "symlink": makeZip([]string{"disk"}, os.ModeSymlink|0777, disk), "directory": makeZip([]string{"disk/"}, os.ModeDir|0755, nil), "not qcow2": makeZip([]string{"disk"}, 0600, []byte("arbitrary")), "CRC": corrupt, "encrypted": encrypted, "truncated": truncated,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeZIPDisk(data, maxZIPDiskSize); err == nil {
				t.Fatal("invalid ZIP accepted")
			}
		})
	}
	good := makeZip([]string{"../never-written.qcow2"}, 0600, disk)
	if _, err := decodeZIPDisk(good, int64(len(disk)-1)); err == nil {
		t.Fatal("oversized ZIP accepted")
	}
	got, err := decodeZIPDisk(good, int64(len(disk)))
	if err != nil || !bytes.Equal(got, disk) {
		t.Fatalf("bounded single disk=%v", err)
	}
}

func TestKernelSelectionDoesNotHideReadErrors(t *testing.T) {
	fail := errors.New("unreadable kernel")
	volume := stubVolume{"flatkc": {err: fail}, "vmlinuz": {data: []byte("alternate")}, "rootfs.gz": {data: []byte("rootfs")}}
	got := readRequiredMembers(volume)
	if !errors.Is(got.Kernel.Err, fail) || got.Kernel.Name != "flatkc" {
		t.Fatalf("read error hidden: %+v", got.Kernel)
	}
	volume["flatkc"] = struct {
		data []byte
		err  error
	}{err: diskimage.ErrNotFound}
	got = readRequiredMembers(volume)
	if got.Err() != nil || got.Kernel.Name != "vmlinuz" {
		t.Fatalf("alternate kernel not selected: %+v", got.Kernel)
	}
}

func TestStandaloneXZRootfsValidation(t *testing.T) {
	plain, err := gunzipOuter(syntheticNewcRootfs(t, true))
	if err != nil {
		t.Fatal(err)
	}
	data := xzBytes(t, plain)
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			dir := t.TempDir()
			kernel, input, output := filepath.Join(dir, "vmlinuz"), filepath.Join(dir, "rootfs.gz"), filepath.Join(dir, "decoded")
			if err := os.WriteFile(kernel, []byte("unused for a plain rootfs"), 0600); err != nil {
				t.Fatal(err)
			}
			payload := data
			if !valid {
				payload = data[:len(data)-4]
			}
			if err := os.WriteFile(input, payload, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := captureStdout(t, func() error { return cmdRootfs(context.Background(), []string{"-o", output, kernel, input}) })
			if valid {
				got, readErr := os.ReadFile(output)
				if err != nil || readErr != nil || !bytes.Equal(got, payload) {
					t.Fatalf("valid XZ: %v %v", err, readErr)
				}
			} else {
				if err == nil {
					t.Fatal("truncated XZ accepted")
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("failed XZ published output")
				}
			}
		})
	}
}
