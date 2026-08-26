package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mosajjal/fortitool/internal/archive"
)

func cmdUnpack(_ context.Context, args []string) error {
	fs := newCommandFlagSet("unpack", nil)
	out := fs.String("o", "", "output directory (required)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fortitool unpack -- extract a gzip+tar or xz+tar archive

Format is auto-detected from the filename extension, falling back to
sniffing the gzip magic bytes, falling back to assuming plain tar. This
is a generic utility for the tar/xz archives found inside a decrypted
FortiOS rootfs (bin.tar.xz, usr.tar.xz, migadmin.tar.xz, ...) and for
datafs.tar.gz, but works on any gzip+tar / xz+tar file. Symlinks are
confined to the extraction tree (absolute archive targets are safely
rebased within it); tar entries containing ".." path components are
rejected rather than extracted.

USAGE
  fortitool unpack -o OUTDIR <archive>

FLAGS
  -o OUTDIR   output directory (required; must not already exist; published
              only after complete extraction, private to the invoking identity:
              mode 0700 on Unix and a protected per-user DACL on Windows)

EXAMPLES
  fortitool unpack -o rootfs/ rootfs.gz.dec
  fortitool unpack -o rootfs/bin rootfs/bin.tar.xz

EXIT CODES
  0  archive unpacked successfully
  1  input could not be read or extracted
  2  invalid flags, missing -o, or wrong number of positional arguments
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usage(err)
	}
	if fs.NArg() != 1 || *out == "" {
		fs.Usage()
		return usagef("usage: fortitool unpack -o OUTDIR <archive>")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	staged, err := newStagedOutputDir(*out)
	if err != nil {
		return err
	}
	defer staged.Cleanup()
	name := strings.ToLower(fs.Arg(0))
	switch {
	case strings.HasSuffix(name, ".tar.xz") || strings.HasSuffix(name, ".txz"):
		err = archive.ExtractXZTar(data, staged.temp)
	case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".gz"):
		err = archive.ExtractGzipTar(data, staged.temp)
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		err = archive.ExtractGzipTar(data, staged.temp)
	default:
		err = archive.Untar(bytes.NewReader(data), staged.temp)
	}
	if err != nil {
		return err
	}
	if err := staged.Commit(); err != nil {
		return err
	}
	fmt.Printf("[+] unpacked to %s\n", terminalText(*out))
	return nil
}
