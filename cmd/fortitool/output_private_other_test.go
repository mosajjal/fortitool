//go:build !windows

package main

import (
	"os"
	"testing"
)

func assertPrivateDirectory(t *testing.T, name string) {
	t.Helper()
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("published tree mode = %04o, want 0700", got)
	}
}

func assertPrivateFile(t *testing.T, name string) {
	t.Helper()
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("standalone output mode = %04o, want 0600", got)
	}
}
