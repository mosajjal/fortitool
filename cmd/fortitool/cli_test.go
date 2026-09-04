package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const cliHelperEnvironment = "FORTITOOL_CLI_HELPER_PROCESS"

func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv(cliHelperEnvironment) != "1" {
		return
	}
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		os.Exit(99)
	}
	os.Exit(runCLI(context.Background(), os.Args[separator+1:]))
}

func TestCLIExitCodeContract(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	output := filepath.Join(t.TempDir(), "output")
	emptyDir := t.TempDir()
	missingError := "no such file"
	if runtime.GOOS == "windows" {
		missingError = "cannot find the file specified"
	}

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantText string
	}{
		{name: "top-level help", args: []string{"-h"}, wantCode: 0, wantText: "USAGE"},
		{name: "top-level help alias", args: []string{"help"}, wantCode: 0, wantText: "COMMANDS"},
		{name: "top-level help alias extra argument", args: []string{"help", "extra"}, wantCode: 2, wantText: "usage: fortitool help"},
		{name: "version", args: []string{"--version"}, wantCode: 0, wantText: "fortitool " + version},
		{name: "version extra argument", args: []string{"version", "extra"}, wantCode: 2, wantText: "usage: fortitool version"},
		{name: "missing command", wantCode: 2, wantText: "USAGE"},
		{name: "unknown command", args: []string{"unknown"}, wantCode: 2, wantText: "unknown command"},

		{name: "decrypt help", args: []string{"decrypt", "-h"}, wantCode: 0, wantText: "fortitool decrypt --"},
		{name: "decrypt missing arguments", args: []string{"decrypt"}, wantCode: 2, wantText: "usage: fortitool decrypt"},
		{name: "decrypt extra argument", args: []string{"decrypt", "-o", output, missing, "extra"}, wantCode: 2, wantText: "usage: fortitool decrypt"},
		{name: "decrypt runtime failure", args: []string{"decrypt", "-o", output, missing}, wantCode: 1, wantText: missingError},

		{name: "inspect help", args: []string{"inspect", "-h"}, wantCode: 0, wantText: "fortitool inspect --"},
		{name: "inspect missing argument", args: []string{"inspect"}, wantCode: 2, wantText: "usage: fortitool inspect"},
		{name: "inspect extra argument", args: []string{"inspect", missing, "extra"}, wantCode: 2, wantText: "usage: fortitool inspect"},
		{name: "inspect runtime failure", args: []string{"inspect", missing}, wantCode: 1, wantText: "input file does not exist"},

		{name: "l1 help", args: []string{"l1", "-h"}, wantCode: 0, wantText: "fortitool l1 --"},
		{name: "l1 missing argument", args: []string{"l1"}, wantCode: 2, wantText: "usage: fortitool l1"},
		{name: "l1 extra argument", args: []string{"l1", missing, "extra"}, wantCode: 2, wantText: "usage: fortitool l1"},
		{name: "l1 invalid flag", args: []string{"l1", "--invalid"}, wantCode: 2, wantText: "flag provided but not defined"},
		{name: "l1 runtime failure", args: []string{"l1", missing}, wantCode: 1, wantText: missingError},

		{name: "rootfs help", args: []string{"rootfs", "-h"}, wantCode: 0, wantText: "fortitool rootfs --"},
		{name: "rootfs missing arguments", args: []string{"rootfs", missing}, wantCode: 2, wantText: "usage: fortitool rootfs"},
		{name: "rootfs extra argument", args: []string{"rootfs", missing, missing, "extra"}, wantCode: 2, wantText: "usage: fortitool rootfs"},
		{name: "rootfs runtime failure", args: []string{"rootfs", missing, missing}, wantCode: 1, wantText: missingError},

		{name: "unpack help", args: []string{"unpack", "-h"}, wantCode: 0, wantText: "fortitool unpack --"},
		{name: "unpack missing arguments", args: []string{"unpack"}, wantCode: 2, wantText: "usage: fortitool unpack"},
		{name: "unpack missing output", args: []string{"unpack", missing}, wantCode: 2, wantText: "usage: fortitool unpack"},
		{name: "unpack extra argument", args: []string{"unpack", "-o", output, missing, "extra"}, wantCode: 2, wantText: "usage: fortitool unpack"},
		{name: "unpack runtime failure", args: []string{"unpack", "-o", output, missing}, wantCode: 1, wantText: missingError},

		{name: "config help", args: []string{"config", "-h"}, wantCode: 0, wantText: "fortitool config decrypt --"},
		{name: "config missing subcommand", args: []string{"config"}, wantCode: 2, wantText: "usage: fortitool config decrypt"},
		{name: "config unknown subcommand", args: []string{"config", "unknown"}, wantCode: 2, wantText: "usage: fortitool config decrypt"},
		{name: "config decrypt help", args: []string{"config", "decrypt", "-h"}, wantCode: 0, wantText: "fortitool config decrypt --"},
		{name: "config decrypt missing input", args: []string{"config", "decrypt"}, wantCode: 2, wantText: "usage: fortitool config decrypt"},
		{name: "config decrypt extra input", args: []string{"config", "decrypt", "AAAA", "BBBB"}, wantCode: 2, wantText: "usage: fortitool config decrypt"},
		{name: "config decrypt runtime failure", args: []string{"config", "decrypt", "not-base64"}, wantCode: 1, wantText: "base64 decode"},

		{name: "pkg help", args: []string{"pkg", "-h"}, wantCode: 0, wantText: "fortitool pkg --"},
		{name: "pkg missing subcommand", args: []string{"pkg"}, wantCode: 2, wantText: "usage: fortitool pkg"},
		{name: "pkg unknown subcommand", args: []string{"pkg", "unknown"}, wantCode: 2, wantText: "usage: fortitool pkg"},
		{name: "pkg inspect help", args: []string{"pkg", "inspect", "-h"}, wantCode: 0, wantText: "fortitool pkg --"},
		{name: "pkg inspect missing signature", args: []string{"pkg", "inspect"}, wantCode: 2, wantText: "usage: fortitool pkg inspect"},
		{name: "pkg inspect extra signature", args: []string{"pkg", "inspect", missing, "extra"}, wantCode: 2, wantText: "usage: fortitool pkg inspect"},
		{name: "pkg inspect runtime failure", args: []string{"pkg", "inspect", missing}, wantCode: 1, wantText: missingError},
		{name: "pkg scan help", args: []string{"pkg", "scan", "-h"}, wantCode: 0, wantText: "fortitool pkg --"},
		{name: "pkg scan missing directory", args: []string{"pkg", "scan"}, wantCode: 2, wantText: "usage: fortitool pkg scan"},
		{name: "pkg scan extra directory", args: []string{"pkg", "scan", emptyDir, "extra"}, wantCode: 2, wantText: "usage: fortitool pkg scan"},
		{name: "pkg scan runtime failure", args: []string{"pkg", "scan", missing}, wantCode: 1, wantText: missingError},
		{name: "pkg scan success", args: []string{"pkg", "scan", emptyDir}, wantCode: 0, wantText: "Scanned 0 regular files"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runCLISubprocess(t, test.args, "")
			if result.code != test.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", result.code, test.wantCode, result.stdout, result.stderr)
			}
			if combined := result.stdout + result.stderr; !strings.Contains(combined, test.wantText) {
				t.Fatalf("output does not contain %q\nstdout:\n%s\nstderr:\n%s", test.wantText, result.stdout, result.stderr)
			}
		})
	}
}

func TestConfigCiphertextSources(t *testing.T) {
	secret := "line one\nline two"
	ciphertext := encryptConfigSecretForCLI(t, secret)
	inputFile := filepath.Join(t.TempDir(), "ciphertext.txt")
	if err := os.WriteFile(inputFile, []byte(ciphertext+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		args     []string
		stdin    string
		wantCode int
		wantText string
	}{
		{name: "stdin", args: []string{"config", "decrypt", "--stdin"}, stdin: ciphertext + "\n", wantCode: 0, wantText: "line one\\x0aline two"},
		{name: "file", args: []string{"config", "decrypt", "--file", inputFile}, wantCode: 0, wantText: "line one\\x0aline two"},
		{name: "argv compatibility", args: []string{"config", "decrypt", ciphertext}, wantCode: 0, wantText: "line one\\x0aline two"},
		{name: "stdin and argv", args: []string{"config", "decrypt", "--stdin", ciphertext}, stdin: ciphertext, wantCode: 2, wantText: "select exactly one ciphertext source"},
		{name: "file and argv", args: []string{"config", "decrypt", "--file", inputFile, ciphertext}, wantCode: 2, wantText: "select exactly one ciphertext source"},
		{name: "stdin and file", args: []string{"config", "decrypt", "--stdin", "--file", inputFile}, stdin: ciphertext, wantCode: 2, wantText: "select exactly one ciphertext source"},
		{name: "empty file path", args: []string{"config", "decrypt", "--file="}, wantCode: 2, wantText: "FILE must not be empty"},
		{name: "empty file path and argv", args: []string{"config", "decrypt", "--file=", ciphertext}, wantCode: 2, wantText: "select exactly one ciphertext source"},
		{name: "empty stdin", args: []string{"config", "decrypt", "--stdin"}, wantCode: 1, wantText: "ciphertext input is empty"},
		{name: "internal whitespace", args: []string{"config", "decrypt", "--stdin"}, stdin: "AAAA BBBB\n", wantCode: 1, wantText: "internal whitespace"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runCLISubprocess(t, test.args, test.stdin)
			if result.code != test.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", result.code, test.wantCode, result.stdout, result.stderr)
			}
			if combined := result.stdout + result.stderr; !strings.Contains(combined, test.wantText) {
				t.Fatalf("output does not contain %q\nstdout:\n%s\nstderr:\n%s", test.wantText, result.stdout, result.stderr)
			}
			if strings.Contains(result.stdout, "\nline two") {
				t.Fatalf("decrypted control byte was written literally:\n%s", result.stdout)
			}
		})
	}
}

func TestReadConfigCiphertextLimit(t *testing.T) {
	input := strings.Repeat("A", maxConfigCiphertextBytes+1)
	if _, err := readConfigCiphertext(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized input error = %v", err)
	}
}

func TestTerminalText(t *testing.T) {
	input := "plain\tline\n\x1b\x7f\u0085\u202e\u2066" + string([]byte{0xff})
	want := `plain\x09line\x0a\x1b\x7f\x85\u202e\u2066\xff`
	if got := terminalText(input); got != want {
		t.Fatalf("terminalText() = %q, want %q", got, want)
	}
}

func TestCLIErrorEscapesTerminalControls(t *testing.T) {
	result := runCLISubprocess(t, []string{"l1", "--invalid\x1bflag"}, "")
	if result.code != 2 {
		t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	if strings.Contains(result.stderr, "\x1b") {
		t.Fatalf("stderr contains a literal escape byte:\n%s", result.stderr)
	}
	if !strings.Contains(result.stderr, `\x1b`) {
		t.Fatalf("stderr does not contain an escaped control byte:\n%s", result.stderr)
	}
}

func encryptConfigSecretForCLI(t *testing.T, secret string) string {
	t.Helper()
	padding := aes.BlockSize - len(secret)%aes.BlockSize
	plaintext := append([]byte(secret), bytes.Repeat([]byte{byte(padding)}, padding)...)
	ivPrefix := []byte{1, 2, 3, 4}
	iv := make([]byte, aes.BlockSize)
	copy(iv, ivPrefix)
	block, err := aes.NewCipher([]byte("Mary had a littl"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return base64.StdEncoding.EncodeToString(append(ivPrefix, ciphertext...))
}

type cliResult struct {
	code   int
	stdout string
	stderr string
}

func runCLISubprocess(t *testing.T, args []string, stdin string) cliResult {
	return runCLISubprocessAt(t, args, stdin, "", nil)
}

func runCLISubprocessAt(t *testing.T, args []string, stdin, dir string, extraEnv []string) cliResult {
	t.Helper()
	helperArgs := append([]string{"-test.run=^TestCLIHelperProcess$", "--"}, args...)
	cmd := exec.Command(os.Args[0], helperArgs...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Env = append(cmd.Env, cliHelperEnvironment+"=1")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running CLI helper: %v", err)
		}
		code = exitErr.ExitCode()
	}
	return cliResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}
