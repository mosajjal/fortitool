//go:build !linux

package main

import "fmt"

func renameNew(oldPath, newPath string) error {
	return fmt.Errorf("atomic no-replace directory publication is unsupported on this platform")
}
