// Command fortitool is a single self-contained binary for decrypting and
// unpacking supported FortiGate/FortiWiFi firmware and FortiAnalyzer/
// FortiManager KVM installation disks. It also handles FortiOS config-backup
// secrets and FortiGuard PKCS#7 signatures. Build with CGO_ENABLED=0 for a
// static binary with no external runtime tools.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

var version = "0.1.0"

// command describes one subcommand for the top-level help listing and
// dispatch table.
type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

var commands = []command{
	{"decrypt", "extract .out or FAZ/FMG KVM disks; --boot-only preserves boot files", cmdDecrypt},
	{"inspect", "describe one firmware image read-only, including partial support", cmdInspect},
	{"l1", "outer .out XOR layer only (known-plaintext attack)", cmdL1},
	{"rootfs", "supported rootfs.gz crypto with flatkc or vmlinuz, auto-detected", cmdRootfs},
	{"unpack", "generic archive unpack: gzip+tar or xz+tar -> directory", cmdUnpack},
	{"config", "decrypt a config-backup `ENC <base64>` secret field", cmdConfig},
	{"pkg", "inspect/verify FortiGuard sub-component PKCS#7 signatures", cmdPkg},
}

func main() {
	os.Exit(runCLI(context.Background(), os.Args[1:]))
}

func runCLI(ctx context.Context, args []string) int {
	if len(args) < 1 {
		printTopLevelHelp(os.Stdout)
		return 2
	}
	cmd := args[0]
	cmdArgs := args[1:]

	if cmd == "-h" || cmd == "--help" {
		printTopLevelHelp(os.Stdout)
		return 0
	}
	if cmd == "help" {
		if len(cmdArgs) != 0 {
			fmt.Fprintln(os.Stderr, "fortitool: usage: fortitool help")
			return 2
		}
		printTopLevelHelp(os.Stdout)
		return 0
	}
	if cmd == "--version" || cmd == "version" {
		if len(cmdArgs) != 0 {
			fmt.Fprintln(os.Stderr, "fortitool: usage: fortitool version")
			return 2
		}
		fmt.Println("fortitool", version)
		return 0
	}

	for _, c := range commands {
		if c.name != cmd {
			continue
		}
		if err := c.run(ctx, cmdArgs); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %s\n", terminalText(err.Error()))
			return commandExitCode(err)
		}
		return 0
	}

	fmt.Fprintf(os.Stderr, "fortitool: unknown command %q\n\n", cmd)
	printTopLevelHelp(os.Stderr)
	return 2
}

type usageError struct {
	err error
}

func (e *usageError) Error() string {
	return e.err.Error()
}

func (e *usageError) Unwrap() error {
	return e.err
}

func usage(err error) error {
	return &usageError{err: err}
}

func usagef(format string, args ...any) error {
	return usage(fmt.Errorf(format, args...))
}

func commandExitCode(err error) int {
	var usage *usageError
	if errors.As(err, &usage) {
		return 2
	}
	return 1
}

func printTopLevelHelp(w io.Writer) {
	fmt.Fprintf(w, `fortitool %s -- Fortinet firmware decryption/unpacking, one static binary, no OS deps

WHAT THIS IS
  Supports FortiGate/FortiWiFi FortiOS firmware and tested FortiAnalyzer/
  FortiManager KVM installation disks (bare QCOW2 or single-disk ZIP).
  Config-secret decryption covers FortiOS backups. See the README for exact
  product/build coverage and remaining limits.

  Firmware ships with multiple, version-dependent encryption
  layers (see https://github.com/mosajjal/fortitool#supported-firmware for
  the full matrix). Historically, decrypting a single firmware image meant
  chaining several different tools (forticrack, fgx, forticrack_v8,
  decrypt-fortigate-rootfs, ...) plus OS binaries (openssl, xz, tar, cpio,
  debugfs, vmlinux-to-elf, python3) picked by hand based on the firmware
  version and CPU architecture. fortitool auto-detects the crypto era and
  does the whole pipeline in one process, in pure Go: no runtime OS package
  dependencies at all (verify with 'ldd fortitool' -> "not a dynamic
  executable" when built with CGO_ENABLED=0).

USAGE
  fortitool <command> [flags] [arguments]

  IMPORTANT: flags must come BEFORE positional arguments (Go's flag
  package does not permute argv like getopt does), e.g.:
    fortitool decrypt -o outdir image.out        (correct)
    fortitool decrypt image.out -o outdir        (WRONG: -o is ignored)

COMMANDS
`, version)
	for _, c := range commands {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, `
Run 'fortitool <command> -h' for a full description, flags, and examples
for that command.

EXIT CODES
  0  success (inspect also uses 0 for a readable partial/unsupported result)
  1  ran, but failed (e.g. no valid key found or file not found)
  2  usage error (unknown command / missing required argument)

For everything that's verified against real firmware vs. architecturally
ready but not yet run against a sample, see the README.
`)
}
