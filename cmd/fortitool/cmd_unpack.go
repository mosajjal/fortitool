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
preserved as-is (including absolute targets like "/sbin/init", which is
normal for a Linux rootfs tree); tar entries containing ".." path
components are rejected rather than extracted.

USAGE
  fortitool unpack -o OUTDIR <archive>

FLAGS
  -o OUTDIR   output directory (required)

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
	name := strings.ToLower(fs.Arg(0))
	switch {
	case strings.HasSuffix(name, ".tar.xz") || strings.HasSuffix(name, ".txz"):
		err = archive.ExtractXZTar(data, *out)
	case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".gz"):
		err = archive.ExtractGzipTar(data, *out)
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		err = archive.ExtractGzipTar(data, *out)
	default:
		err = archive.Untar(bytes.NewReader(data), *out)
	}
	if err != nil {
		return err
	}
	fmt.Printf("[+] unpacked to %s\n", terminalText(*out))
	return nil
}
