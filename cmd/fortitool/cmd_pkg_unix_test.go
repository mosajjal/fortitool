//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestCmdPkgScanDoesNotOpenSymlinksOrSpecialFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	writeTestFile(t, outside, []byte{0x7f, 'E', 'L', 'F'})
	if err := os.Symlink(outside, filepath.Join(root, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "named-pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "regular"), []byte("regular data"))

	stdout, _, err := captureCommandOutput(t, func() error { return cmdPkgScan([]string{root}) })
	if err != nil {
		t.Fatalf("cmdPkgScan: %v", err)
	}
	for _, want := range []string{
		"Scanned 1 regular file",
		"skipped 1 symlink and 1 special file",
		"== symlink (not scanned) (1) ==",
		"== special file (not scanned) (1) ==",
		"outside-link",
		"named-pipe",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout does not contain %q:\n%s", want, stdout)
		}
	}
}
