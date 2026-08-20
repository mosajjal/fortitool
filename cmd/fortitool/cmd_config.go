package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/mosajjal/fortitool/internal/configsecret"
)

const configHelp = `fortitool config decrypt -- decrypt a FortiOS config-backup 'ENC' secret

FortiOS config backups embed secrets (passwords, PSKs, certificate
passphrases) as 'set <field> ENC <base64>' lines. This decrypts one such
base64 blob using the legacy hardcoded AES-128-CBC key from CVE-2019-6693
("Mary had a littl"). Contrary to the commonly repeated belief that this
key was rotated at FortiOS 6.2, it was NOT -- that belief conflates it
with a separate, opt-in whole-backup-file passphrase feature
('private-data-encryption'). The legacy key still works through at least
FortiOS 7.2.3. It changed at 7.4 (build 2731) to a key that has not been
identified yet; blobs from that era are detected (via an unencrypted
8-byte trailer marker) and reported as such rather than silently failing.

Two blob layouts are auto-detected:
  - cert-fixed144: certificate/PKI password fields, a fixed 144-byte
    zero-padded buffer. Validated against real device data.
  - pkcs7-variable: ordinary short admin/user passwords, standard
    PKCS#7-padded ciphertext. Less thoroughly validated -- treat results
    from this path with more caution.

USAGE
  fortitool config decrypt <base64-blob>

  Pass just the base64 part after "ENC " from the config file, e.g. for
  a line 'set password ENC AK17UY25Ahhm2bZ5zcMn...==', pass
  'AK17UY25Ahhm2bZ5zcMn...=='.

EXAMPLE
  fortitool config decrypt AK17UY25Ahhm2bZ5zcMnW5RtgnPP3hupkQ1v6GP2LDtDu0=

EXIT CODES
  0  decrypted (secret printed), OR a recognized-but-unsupported case
     (>=7.4 marker present, or neither known layout matched) -- check
     stdout for which
  1  malformed input (bad base64, too short to contain an IV)
`

func cmdConfig(_ context.Context, args []string) error {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(os.Stderr, configHelp)
		return nil
	}
	if len(args) < 2 || args[0] != "decrypt" {
		fmt.Fprint(os.Stderr, configHelp)
		return fmt.Errorf("usage: fortitool config decrypt <base64-blob>")
	}
	res, err := configsecret.DecryptLegacy(args[1])
	if err != nil {
		if errors.Is(err, configsecret.ErrEra74Unidentified) || errors.Is(err, configsecret.ErrNotLegacyFormat) {
			fmt.Printf("[-] %v\n", err)
			return nil
		}
		return err
	}
	fmt.Printf("[+] secret: %s\n", res.Secret)
	fmt.Printf("    layout: %s\n", res.Layout)
	return nil
}
