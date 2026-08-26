//go:build !windows

package main

import (
	"fmt"
	"os"
)

func createPrivateTempDir(dir, pattern string) (string, func() error, func(), error) {
	name, err := os.MkdirTemp(dir, pattern)
	if err != nil {
		return "", nil, nil, err
	}
	if err := os.Chmod(name, 0o700); err != nil {
		_ = os.Remove(name)
		return "", nil, nil, err
	}
	return name, nil, nil, nil
}

func createPrivateTempFile(dir, pattern string, mode os.FileMode) (*os.File, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}

func publishPrivateTempFile(f *os.File, temp, name string) error {
	if err := f.Close(); err != nil {
		return err
	}
	// Publishing with a hard link is atomic and fails if another process
	// creates the destination between the initial check and this point.
	if err := os.Link(temp, name); err != nil {
		return fmt.Errorf("publishing output file: %w", err)
	}
	return nil
}
