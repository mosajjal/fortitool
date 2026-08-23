package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
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
  fortitool pkg inspect [--content <payload>] <sig.x>
      Parse a detached signature: list digest algorithms and every
      certificate's subject/issuer. With --content, also verifies the
      signature against that payload file. Verification succeeds only
      when at least one SignerInfo is present and every SignerInfo validates.
      This is a cryptographic integrity check against the certificates in
      the wrapper; it does NOT build or validate a trust chain to a root CA
      (matching 'openssl smime -verify -noverify'). It also extracts embedded
      FortiGuard package IDs (e.g. "06004000NIDS00105-000070059-2601051815").

  fortitool pkg scan <dir>
      Walk a directory (e.g. an extracted datafs/) without following
      symlinks. Classify regular files from at most their first 4096 bytes
      as ELF, gzip, PKCS#7 SignedData, or entropy-based buckets
      ("encrypted?", "structured", "data"). Symlinks and special files
      are reported but never opened. Suggests the matching 'pkg inspect'
      invocation for any signature it finds.

EXAMPLES
  fortitool pkg scan firmware/work/v7411/fs/datafs
  fortitool pkg inspect --content lib/libips.so.new lib/libips.so.new.x

EXIT CODES
  0  inspection or scan succeeded
  1  input could not be read, parsed, scanned, or cryptographically verified
  2  invalid flags, unknown subcommand, or wrong number of arguments
`

func cmdPkg(_ context.Context, args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(os.Stderr, pkgHelp)
		return nil
	}
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, pkgHelp)
		return usagef("usage: fortitool pkg <inspect|scan> ...")
	}
	switch args[0] {
	case "inspect":
		return cmdPkgInspect(args[1:])
	case "scan":
		return cmdPkgScan(args[1:])
	default:
		fmt.Fprint(os.Stderr, pkgHelp)
		return usagef("usage: fortitool pkg <inspect|scan> ...")
	}
}

func cmdPkgInspect(args []string) error {
	fs := newCommandFlagSet("pkg inspect", nil)
	content := fs.String("content", "", "payload file the detached signature covers")
	fs.Usage = func() { fmt.Fprint(os.Stderr, pkgHelp) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usage(err)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return usagef("usage: fortitool pkg inspect [--content <payload>] <sig.x>")
	}
	contentSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "content" {
			contentSet = true
		}
	})
	if contentSet && *content == "" {
		fs.Usage()
		return usagef("--content requires a non-empty path")
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
	fmt.Printf("[+] %s: PKCS#7 SignedData (%d bytes)\n", terminalText(sigPath), len(der))
	fmt.Printf("    digest algorithms: %v\n", sd.DigestAlgorithms)
	for _, cert := range sd.Certificates {
		fmt.Printf("    cert: %s\n", terminalText(cert.Subject.String()))
		fmt.Printf("          <- %s\n", terminalText(cert.Issuer.String()))
	}

	if !contentSet {
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
			mark(r.Valid), i, terminalText(*content), terminalText(r.Signer.DigestAlgorithm),
			terminalText(r.Signer.SignatureAlgorithm), terminalText(r.Signer.IssuerDN))
		if !r.Valid {
			fmt.Printf("      reason: %s\n", terminalText(r.Reason))
		}
	}
	verificationErr := requireAllSignersValid(results)
	if verificationErr != nil {
		fmt.Printf("[-] cryptographic integrity: FAILED (%v)\n", verificationErr)
	} else {
		fmt.Printf("[+] cryptographic integrity: PASSED (%d of %d signers valid)\n", len(results), len(results))
	}
	fmt.Println("[i] trust chain: NOT VALIDATED (certificates are not anchored to trusted roots)")
	for _, id := range pkcs7.FindPackageIDs(payload, 8) {
		fmt.Printf("    package id: %s\n", id)
	}
	fmt.Printf("    payload entropy: %.2f bits/byte\n", entropy(payload))
	return verificationErr
}

func requireAllSignersValid(results []pkcs7.VerifyResult) error {
	if len(results) == 0 {
		return fmt.Errorf("no SignerInfo entries")
	}
	invalid := 0
	for _, result := range results {
		if !result.Valid {
			invalid++
		}
	}
	if invalid != 0 {
		return fmt.Errorf("%d of %d SignerInfo entries invalid; every signer must validate", invalid, len(results))
	}
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
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, pkgHelp)
		return usagef("usage: fortitool pkg scan <dir>")
	}
	root := args[0]
	scan, err := scanPackageFiles(root, filepath.WalkDir)
	if err != nil {
		return err
	}
	buckets := scan.buckets

	fmt.Printf("Scanned %d regular file%s under %s; skipped %d symlink%s and %d special file%s\n\n",
		scan.regularFiles, pluralSuffix(scan.regularFiles), terminalText(root),
		scan.symlinks, pluralSuffix(scan.symlinks), scan.specialFiles, pluralSuffix(scan.specialFiles))

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
			fmt.Printf("   %12d  %s\n", e.size, terminalText(e.path))
		}
		fmt.Println()
		if kind == "PKCS#7 SignedData" && firstSig == "" && len(entries) > 0 {
			firstSig = entries[0].path
		}
	}
	if firstSig != "" {
		signaturePath := firstSig
		if !filepath.IsAbs(signaturePath) {
			signaturePath = filepath.Join(root, signaturePath)
		}
		base := signaturePath
		if len(base) > 2 && base[len(base)-2:] == ".x" {
			base = base[:len(base)-2]
		}
		fmt.Println(pkgInspectSuggestion(runtime.GOOS, base, signaturePath))
	}
	return nil
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

const classificationPrefixSize = 4096

const (
	symlinkKind = "symlink (not scanned)"
	specialKind = "special file (not scanned)"
)

type packageScan struct {
	buckets      map[string][]fileEntry
	regularFiles int
	symlinks     int
	specialFiles int
}

type walkDirFunc func(string, fs.WalkDirFunc) error

func scanPackageFiles(root string, walkDir walkDirFunc) (packageScan, error) {
	result := packageScan{buckets: map[string][]fileEntry{}}
	err := walkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walking %s: %w", path, walkErr)
		}
		if entry.IsDir() {
			return nil
		}

		rel := relPath(root, path)
		if entry.Type()&os.ModeSymlink != 0 {
			result.buckets[symlinkKind] = append(result.buckets[symlinkKind], fileEntry{path: rel})
			result.symlinks++
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("reading file information for %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			result.buckets[specialKind] = append(result.buckets[specialKind], fileEntry{path: rel, size: info.Size()})
			result.specialFiles++
			return nil
		}

		kind, err := classify(path)
		if err != nil {
			return fmt.Errorf("classifying %s: %w", path, err)
		}
		result.buckets[kind] = append(result.buckets[kind], fileEntry{path: rel, size: info.Size()})
		result.regularFiles++
		return nil
	})
	if err != nil {
		return packageScan{}, err
	}
	return result, nil
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

func classify(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return classifyReader(f)
}

func classifyReader(r io.Reader) (string, error) {
	head := make([]byte, classificationPrefixSize)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", err
	}
	head = head[:n]

	if len(head) >= 4 && bytes.Equal(head[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return "ELF", nil
	}
	if len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		return "gzip", nil
	}
	if len(head) >= 6 && bytes.Equal(head[:6], []byte("070701")) {
		return "cpio", nil
	}
	if len(head) >= 2 && (head[0] == 0x30 && (head[1] == 0x80 || head[1] == 0x82)) {
		if bytes.Contains(head, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}) {
			return "PKCS#7 SignedData", nil
		}
		return "ASN.1 DER", nil
	}
	e := entropy(head)
	switch {
	case e > 7.9:
		return fmt.Sprintf("encrypted? (entropy %.2f)", e), nil
	case e < 3.0:
		return fmt.Sprintf("structured (entropy %.2f)", e), nil
	default:
		return fmt.Sprintf("data (entropy %.2f)", e), nil
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
