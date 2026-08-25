//go:build !linux

package main

func renameNew(oldPath, newPath string) error {
	return renamePortable(oldPath, newPath)
}
