package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/mosajjal/fortitool/internal/configsecret"
)

const configHelp = `fortitool config decrypt -- decrypt a FortiOS config-backup 'ENC' secret

FortiOS config backups embed secrets (passwords, PSKs, certificate
passphrases) as 'set <field> ENC <base64>' lines. This decrypts one such
base64 blob, auto-detecting the crypto era:

  - pre-7.4: legacy hardcoded AES-128-CBC key from CVE-2019-6693 ("Mary
    had a littl"). Contrary to the commonly repeated belief that this key
    was rotated at FortiOS 6.2, it was NOT -- that belief conflates it
    with a separate, opt-in whole-backup-file passphrase feature
    ('private-data-encryption'). It still works through at least 7.2.3.
  - >=7.4 (build 2731): AES-256-CBC with a hardcoded key (reverse
    engineered from the init monolith; blobs from this era carry an
    unencrypted 8-byte "Yf267vE@" trailer that keys the detection).

Two blob layouts are auto-detected within each era:
  - cert-fixed144: certificate/PKI password fields, a fixed 144-byte
    zero-padded buffer. Validated against real device data.
  - pkcs7-variable: ordinary short admin/user passwords, standard
    PKCS#7-padded ciphertext. Less thoroughly validated -- treat results
    from this path with more caution.

USAGE
  fortitool config decrypt --stdin
  fortitool config decrypt --file FILE
  fortitool config decrypt <base64-blob>    (compatibility only)

  Pass just the base64 part after "ENC ". Prefer --stdin or --file so the
  ciphertext is not exposed in process listings or shell history. Direct
  argv input remains available for compatibility. Exactly one input source
  must be selected.

  Input is limited to 1 MiB; surrounding whitespace is trimmed, and the
  remaining value must be non-empty and contain no whitespace.

FLAGS
  --stdin       read one base64 ciphertext from standard input
  --file FILE   read one base64 ciphertext from FILE

EXAMPLES
  fortitool config decrypt --stdin < ciphertext.txt
  fortitool config decrypt --file ciphertext.txt

EXIT CODES
  0  decrypted (secret printed), OR an unrecognized field type (neither
     known layout matched) -- check stdout for which
  1  malformed input (bad base64, too short to contain an IV)
  2  invalid flags, unknown subcommand, or wrong number of arguments
`

func cmdConfig(_ context.Context, args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(os.Stderr, configHelp)
		return nil
	}
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, configHelp)
		return usagef("usage: fortitool config decrypt (--stdin | --file FILE | <base64-blob>)")
	}
	if args[0] != "decrypt" {
		fmt.Fprint(os.Stderr, configHelp)
		return usagef("usage: fortitool config decrypt (--stdin | --file FILE | <base64-blob>)")
	}
	return cmdConfigDecrypt(args[1:])
}

func cmdConfigDecrypt(args []string) error {
	fs := newCommandFlagSet("config decrypt", nil)
	fromStdin := fs.Bool("stdin", false, "read ciphertext from standard input")
	filePath := fs.String("file", "", "read ciphertext from file")
	fs.Usage = func() { fmt.Fprint(os.Stderr, configHelp) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return usage(err)
	}
	fileSelected := false
	fs.Visit(func(parsed *flag.Flag) {
		if parsed.Name == "file" {
			fileSelected = true
		}
	})
	sources := fs.NArg()
	if *fromStdin {
		sources++
	}
	if fileSelected {
		sources++
	}
	if fs.NArg() > 1 || sources != 1 {
		fs.Usage()
		return usagef("usage: fortitool config decrypt (--stdin | --file FILE | <base64-blob>): select exactly one ciphertext source")
	}
	if fileSelected && *filePath == "" {
		fs.Usage()
		return usagef("usage: fortitool config decrypt --file FILE: FILE must not be empty")
	}

	var ciphertext string
	var err error
	switch {
	case *fromStdin:
		ciphertext, err = readConfigCiphertext(os.Stdin)
	case fileSelected:
		ciphertext, err = readConfigCiphertextFile(*filePath)
	default:
		ciphertext, err = cleanConfigCiphertext([]byte(fs.Arg(0)))
	}
	if err != nil {
		return err
	}
	res, err := configsecret.Decrypt(ciphertext)
	if err != nil {
		if errors.Is(err, configsecret.ErrNotLegacyFormat) || errors.Is(err, configsecret.ErrNotEra74Format) {
			fmt.Printf("[-] %s\n", terminalText(err.Error()))
			return nil
		}
		return err
	}
	fmt.Printf("[+] secret: %s\n", terminalText(string(res.Secret)))
	fmt.Printf("    layout: %s\n", terminalText(string(res.Layout)))
	return nil
}

const maxConfigCiphertextBytes = 1 << 20

func readConfigCiphertextFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return readConfigCiphertext(file)
}

func readConfigCiphertext(reader io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxConfigCiphertextBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading ciphertext: %w", err)
	}
	return cleanConfigCiphertext(data)
}

func cleanConfigCiphertext(data []byte) (string, error) {
	if len(data) > maxConfigCiphertextBytes {
		return "", fmt.Errorf("ciphertext input exceeds %d bytes", maxConfigCiphertextBytes)
	}
	ciphertext := strings.TrimSpace(string(data))
	if ciphertext == "" {
		return "", errors.New("ciphertext input is empty")
	}
	if strings.IndexFunc(ciphertext, unicode.IsSpace) >= 0 {
		return "", errors.New("ciphertext input contains internal whitespace")
	}
	return ciphertext, nil
}
