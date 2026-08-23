package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func formatRecoveredKey(key []byte, show bool) string {
	if show {
		return fmt.Sprintf("key: %s", terminalText(string(key)))
	}
	return "key recovered (redacted; use --show-keys to print)"
}

func formatRootfsKeyDetail(detail string, show bool) string {
	if show {
		return terminalText(detail)
	}
	return "key material redacted (use --show-keys to print)"
}

type stagedOutputDir struct {
	final          string
	temp           string
	createdParents []string
}

func newStagedOutputDir(final string) (*stagedOutputDir, error) {
	if final == "" {
		return nil, fmt.Errorf("empty output directory")
	}
	if _, err := os.Lstat(final); err == nil {
		return nil, fmt.Errorf("output path already exists: %s", final)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	parent := filepath.Dir(final)
	createdParents, err := createOutputParents(parent)
	if err != nil {
		return nil, err
	}
	temp, err := os.MkdirTemp(parent, "."+filepath.Base(final)+".tmp-")
	if err != nil {
		removeCreatedParents(createdParents)
		return nil, err
	}
	if err := os.Chmod(temp, 0o700); err != nil {
		_ = os.RemoveAll(temp)
		removeCreatedParents(createdParents)
		return nil, err
	}
	return &stagedOutputDir{final: final, temp: temp, createdParents: createdParents}, nil
}

func (s *stagedOutputDir) Commit() error {
	if err := renameNew(s.temp, s.final); err != nil {
		return fmt.Errorf("publishing output directory: %w", err)
	}
	s.temp = ""
	s.createdParents = nil
	return nil
}

func (s *stagedOutputDir) Cleanup() {
	if s != nil && s.temp != "" {
		_ = os.RemoveAll(s.temp)
	}
	if s != nil {
		removeCreatedParents(s.createdParents)
		s.createdParents = nil
	}
}

func writeNewFile(name string, data []byte, mode os.FileMode) error {
	if _, err := os.Lstat(name); err == nil {
		return fmt.Errorf("output path already exists: %s", name)
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(name)
	createdParents, err := createOutputParents(parent)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(parent, "."+filepath.Base(name)+".tmp-")
	if err != nil {
		removeCreatedParents(createdParents)
		return err
	}
	temp := f.Name()
	defer func() {
		_ = os.Remove(temp)
		removeCreatedParents(createdParents)
	}()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Publishing with a hard link is atomic and fails if another process
	// creates the destination between the Lstat above and this point.
	if err := os.Link(temp, name); err != nil {
		return fmt.Errorf("publishing output file: %w", err)
	}
	createdParents = nil
	return nil
}

func createOutputParents(parent string) ([]string, error) {
	parent = filepath.Clean(parent)
	var missing []string
	for current := parent; ; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err == nil {
			if !info.IsDir() {
				return nil, fmt.Errorf("output parent is not a directory: %s", current)
			}
			break
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		missing = append(missing, current)
		next := filepath.Dir(current)
		if next == current {
			return nil, fmt.Errorf("no existing ancestor for output parent %s", parent)
		}
	}

	created := make([]string, 0, len(missing))
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0o755); err != nil {
			if os.IsExist(err) {
				if info, statErr := os.Stat(missing[i]); statErr == nil && info.IsDir() {
					continue
				}
			}
			removeCreatedParents(created)
			return nil, err
		}
		created = append(created, missing[i])
	}
	return created, nil
}

func removeCreatedParents(created []string) {
	for i := len(created) - 1; i >= 0; i-- {
		_ = os.Remove(created[i])
	}
}
