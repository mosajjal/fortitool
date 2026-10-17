package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mosajjal/fortitool/internal/archive"
)

var bootArchiveMembers = []string{"syntax.tar.xz", "rootfs-ext.tar.xz", "docker.tar.xz", "widgets.tar.gz"}

// FAZ/FMG bootstrap and application archives can contain different files at
// the same path (notably bin/init). Preserve each layer without inferring a
// boot-time overlay order or relaxing the archive collision checks.
func extractArchiveLayers(sourceDir, layersDir string, members []string) error {
	for _, name := range members {
		input := filepath.Join(sourceDir, name)
		info, err := os.Lstat(input)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("archive layer %s is not a regular file", name)
		}
		data, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		dest := filepath.Join(layersDir, name)
		if strings.HasSuffix(name, ".xz") {
			err = archive.ExtractXZTar(data, dest)
		} else {
			err = archive.ExtractGzipTar(data, dest)
		}
		if err != nil {
			return fmt.Errorf("archive layer %s: %w", name, err)
		}
		fmt.Printf("      %s extracted as a separate archive layer\n", name)
	}
	return nil
}
