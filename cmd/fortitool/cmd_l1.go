package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mosajjal/fortitool/internal/l1"
)

// gunzipOuter decompresses the outer gzip wrapper every .out firmware file
// carries, tolerating trailing garbage the way `gunzip --force` does.
func gunzipOuter(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		// not gzip at all -- some tools pass an already-decompressed image
		return data, nil
	}
	out, err := io.ReadAll(r)
	if len(out) > 0 {
		return out, nil
	}
	return nil, fmt.Errorf("gunzip: %w", err)
}

func cmdL1(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("l1", flag.ContinueOnError)
	out := fs.String("o", "", "output file (default: <input>.decrypted)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fortitool l1 -- decrypt the outer FortiOS ".out" firmware container

Every FortiOS .out image (v6.x through 8.0, every product line) uses the
same outer scheme: a 512-byte-block XOR chain with a 32-byte alphanumeric
key that resets to IV=0xFF at every block boundary. This command recovers
the key live via a known-plaintext attack (32 NUL bytes are known to sit at
offset 48 of the cleartext header) and decrypts the whole image -- no fixed
key list needed, no version/model argument needed. Some images ship
already cleartext at this layer; that's detected and handled too.

Input is the RAW .out file as downloaded (still gzip-wrapped) -- this
command gunzips it internally first.

USAGE
  fortitool l1 [-o FILE] <image.out>

FLAGS
  -o FILE   output path (default: <image.out>.decrypted)

EXAMPLES
  fortitool l1 -o image.img FWF_60E-v7.4.11-build2878-FORTINET.out
  fortitool l1 FWF_60E-v7.4.11-build2878-FORTINET.out
      -> writes FWF_60E-v7.4.11-build2878-FORTINET.out.decrypted

OUTPUT
  Prints the recovered 32-byte alphanumeric key (or "already cleartext")
  to stdout, then writes the decrypted image. The decrypted image still
  contains a raw MBR + ext3 volume -- use 'fortitool decrypt' for the full
  pipeline through to an unpacked rootfs, or read the ext3 volume yourself
  starting at byte offset 512.

EXIT CODES
  0  decrypted successfully (or was already cleartext)
  1  no valid key found -- this usually means the input isn't a FortiOS
     .out image, or uses a crypto scheme this tool doesn't know yet
`)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("missing required argument: <image.out>")
	}
	inPath := fs.Arg(0)
	if *out == "" {
		*out = inPath + ".decrypted"
	}

	raw, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	img, err := gunzipOuter(raw)
	if err != nil {
		return err
	}
	fmt.Printf("[*] loaded image: %d bytes\n", len(img))

	plain, key, wasEncrypted, ok := l1.DecryptAuto(ctx, img)
	if !ok {
		return fmt.Errorf("no valid L1 key found (known-plaintext attack failed)")
	}
	if !wasEncrypted {
		fmt.Println("[+] image is already cleartext at L1")
	} else {
		fmt.Printf("[+] key: %s\n", key)
	}
	if err := os.WriteFile(*out, plain, 0o644); err != nil {
		return err
	}
	fmt.Printf("[+] wrote %s (%d bytes)\n", *out, len(plain))
	return nil
}
