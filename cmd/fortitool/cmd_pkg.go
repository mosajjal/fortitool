package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/mosajjal/fortitool/internal/pkcs7"
)

const pkgHelp = `fortitool pkg -- inspect FortiGuard sub-component PKCS#7 signatures

FortiOS ships IPS/AV engines and rule databases as a payload file plus a
detached ".x" PKCS#7 SignedData signature wrapper (e.g. libips.so.new +
libips.so.new.x), typically dual-signed (an internal Fortinet PKI chain
and a public DigiCert code-signing chain -- two independent SignerInfo
entries). This replaces 'openssl pkcs7 -print_certs' / 'asn1parse' /
'smime -verify' with a pure-Go parser and verifier.

SUBCOMMANDS
  fortitool pkg inspect <sig.x> [--content <payload>]
      Parse a detached signature: list digest algorithms and every
      certificate's subject/issuer. With --content, also verifies the
      signature against that payload file (integrity check only -- this
      does NOT build a trust chain to a root CA, matching
      'openssl smime -verify -noverify') and extracts embedded FortiGuard
      package IDs (e.g. "06004000NIDS00105-000070059-2601051815").

  fortitool pkg scan <dir>
      Walk a directory (e.g. an extracted datafs/) and classify every
      file: ELF, gzip, PKCS#7 SignedData, or entropy-based buckets
      ("encrypted?", "structured", "data") for anything else. Suggests
      the matching 'pkg inspect' invocation for any signature it finds.

EXAMPLES
  fortitool pkg scan firmware/work/v7411/fs/datafs
  fortitool pkg inspect --content lib/libips.so.new lib/libips.so.new.x
`

func cmdPkg(_ context.Context, args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(os.Stderr, pkgHelp)
		return nil
	}
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, pkgHelp)
		return fmt.Errorf("usage: fortitool pkg <inspect|scan> ...")
	}
	switch args[0] {
	case "inspect":
		return cmdPkgInspect(args[1:])
	case "scan":
		return cmdPkgScan(args[1:])
	default:
		fmt.Fprint(os.Stderr, pkgHelp)
		return fmt.Errorf("usage: fortitool pkg <inspect|scan> ...")
	}
}

func cmdPkgInspect(args []string) error {
	fs := flag.NewFlagSet("pkg inspect", flag.ContinueOnError)
	content := fs.String("content", "", "payload file the detached signature covers")
	fs.Usage = func() { fmt.Fprint(os.Stderr, pkgHelp) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("usage: fortitool pkg inspect <sig.x> [--content <payload>]")
	}
	sigPath := fs.Arg(0)

	der, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	sd, err := pkcs7.ParseSignedData(der)
	if err != nil {
		return fmt.Errorf("not a valid PKCS#7 SignedData: %w", err)
	}
	fmt.Printf("[+] %s: PKCS#7 SignedData (%d bytes)\n", sigPath, len(der))
	fmt.Printf("    digest algorithms: %v\n", sd.DigestAlgorithms)
	for _, cert := range sd.Certificates {
		fmt.Printf("    cert: %s\n", cert.Subject)
		fmt.Printf("          <- %s\n", cert.Issuer)
	}

	if *content == "" {
		fmt.Println("[i] pass --content <payload> to verify the signature and read package ids")
		return nil
	}
	payload, err := os.ReadFile(*content)
	if err != nil {
		return err
	}
	results := pkcs7.VerifyDetached(sd, payload)
	for i, r := range results {
		fmt.Printf("[%s] signer %d over %s: digest=%s sig=%s issuer=%s\n",
			mark(r.Valid), i, *content, r.Signer.DigestAlgorithm, r.Signer.SignatureAlgorithm, r.Signer.IssuerDN)
		if !r.Valid {
			fmt.Printf("      reason: %s\n", r.Reason)
		}
	}
	for _, id := range pkcs7.FindPackageIDs(payload, 8) {
		fmt.Printf("    package id: %s\n", id)
	}
	fmt.Printf("    payload entropy: %.2f bits/byte\n", entropy(payload))
	return nil
}

func mark(ok bool) string {
	if ok {
		return "+"
	}
	return "-"
}

func cmdPkgScan(args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(os.Stderr, pkgHelp)
		return nil
	}
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, pkgHelp)
		return fmt.Errorf("usage: fortitool pkg scan <dir>")
	}
	root := args[0]
	buckets := map[string][]fileEntry{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		kind := classify(path)
		buckets[kind] = append(buckets[kind], fileEntry{path: relPath(root, path), size: info.Size()})
		return nil
	})
	if err != nil {
		return err
	}

	total := 0
	for _, v := range buckets {
		total += len(v)
	}
	fmt.Printf("Scanned %d files under %s\n\n", total, root)

	kinds := make([]string, 0, len(buckets))
	for k := range buckets {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)

	var firstSig string
	for _, kind := range kinds {
		entries := buckets[kind]
		sort.Slice(entries, func(i, j int) bool { return entries[i].size > entries[j].size })
		fmt.Printf("== %s (%d) ==\n", kind, len(entries))
		for i, e := range entries {
			if i >= 12 {
				fmt.Printf("   ... and %d more\n", len(entries)-12)
				break
			}
			fmt.Printf("   %12d  %s\n", e.size, e.path)
		}
		fmt.Println()
		if kind == "PKCS#7 SignedData" && firstSig == "" && len(entries) > 0 {
			firstSig = entries[0].path
		}
	}
	if firstSig != "" {
		base := firstSig
		if len(base) > 2 && base[len(base)-2:] == ".x" {
			base = base[:len(base)-2]
		}
		fmt.Printf("Verify detached signatures with e.g.:\n  fortitool pkg inspect %s --content %s\n", firstSig, base)
	}
	return nil
}

type fileEntry struct {
	path string
	size int64
}

func relPath(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return r
}

func classify(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unreadable"
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, _ := f.Read(head)
	head = head[:n]

	if len(head) >= 4 && bytes.Equal(head[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return "ELF"
	}
	if len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		return "gzip"
	}
	if len(head) >= 6 && bytes.Equal(head[:6], []byte("070701")) {
		return "cpio"
	}
	if len(head) >= 2 && (head[0] == 0x30 && (head[1] == 0x80 || head[1] == 0x82)) {
		if bytes.Contains(head, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}) {
			return "PKCS#7 SignedData"
		}
		return "ASN.1 DER"
	}
	e := entropy(head)
	switch {
	case e > 7.9:
		return fmt.Sprintf("encrypted? (entropy %.2f)", e)
	case e < 3.0:
		return fmt.Sprintf("structured (entropy %.2f)", e)
	default:
		return fmt.Sprintf("data (entropy %.2f)", e)
	}
}

func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var h float64
	n := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
