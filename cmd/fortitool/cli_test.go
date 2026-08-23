package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantText string
	}{
		{name: "top-level help", args: []string{"-h"}, wantCode: 0, wantText: "USAGE"},
		{name: "top-level help alias", args: []string{"help"}, wantCode: 0, wantText: "COMMANDS"},
		{name: "version", args: []string{"--version"}, wantCode: 0, wantText: "fortitool " + version},
		{name: "missing command", wantCode: 2, wantText: "USAGE"},
		{name: "unknown command", args: []string{"unknown"}, wantCode: 2, wantText: "unknown command"},

		{name: "decrypt help", args: []string{"decrypt", "-h"}, wantCode: 0, wantText: "fortitool decrypt --"},
		{name: "decrypt missing arguments", args: []string{"decrypt"}, wantCode: 2, wantText: "usage: fortitool decrypt"},
		{name: "decrypt extra argument", args: []string{"decrypt", "-o", output, missing, "extra"}, wantCode: 2, wantText: "usage: fortitool decrypt"},
		{name: "decrypt runtime failure", args: []string{"decrypt", "-o", output, missing}, wantCode: 1, wantText: "no such file"},

		{name: "l1 help", args: []string{"l1", "-h"}, wantCode: 0, wantText: "fortitool l1 --"},
		{name: "l1 missing argument", args: []string{"l1"}, wantCode: 2, wantText: "usage: fortitool l1"},
		{name: "l1 extra argument", args: []string{"l1", missing, "extra"}, wantCode: 2, wantText: "usage: fortitool l1"},
		{name: "l1 invalid flag", args: []string{"l1", "--invalid"}, wantCode: 2, wantText: "flag provided but not defined"},
		{name: "l1 runtime failure", args: []string{"l1", missing}, wantCode: 1, wantText: "no such file"},

		{name: "rootfs help", args: []string{"rootfs", "-h"}, wantCode: 0, wantText: "fortitool rootfs --"},
		{name: "rootfs missing arguments", args: []string{"rootfs", missing}, wantCode: 2, wantText: "usage: fortitool rootfs"},
		{name: "rootfs extra argument", args: []string{"rootfs", missing, missing, "extra"}, wantCode: 2, wantText: "usage: fortitool rootfs"},
		{name: "rootfs runtime failure", args: []string{"rootfs", missing, missing}, wantCode: 1, wantText: "no such file"},

		{name: "unpack help", args: []string{"unpack", "-h"}, wantCode: 0, wantText: "fortitool unpack --"},
		{name: "unpack missing arguments", args: []string{"unpack"}, wantCode: 2, wantText: "usage: fortitool unpack"},
		{name: "unpack missing output", args: []string{"unpack", missing}, wantCode: 2, wantText: "usage: fortitool unpack"},
		{name: "unpack extra argument", args: []string{"unpack", "-o", output, missing, "extra"}, wantCode: 2, wantText: "usage: fortitool unpack"},
		{name: "unpack runtime failure", args: []string{"unpack", "-o", output, missing}, wantCode: 1, wantText: "no such file"},

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
		{name: "pkg inspect runtime failure", args: []string{"pkg", "inspect", missing}, wantCode: 1, wantText: "no such file"},
		{name: "pkg scan help", args: []string{"pkg", "scan", "-h"}, wantCode: 0, wantText: "fortitool pkg --"},
		{name: "pkg scan missing directory", args: []string{"pkg", "scan"}, wantCode: 2, wantText: "usage: fortitool pkg scan"},
		{name: "pkg scan extra directory", args: []string{"pkg", "scan", emptyDir, "extra"}, wantCode: 2, wantText: "usage: fortitool pkg scan"},
		{name: "pkg scan runtime failure", args: []string{"pkg", "scan", missing}, wantCode: 1, wantText: "no such file"},
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

type cliResult struct {
	code   int
	stdout string
	stderr string
}

func runCLISubprocess(t *testing.T, args []string, stdin string) cliResult {
	t.Helper()
	helperArgs := append([]string{"-test.run=^TestCLIHelperProcess$", "--"}, args...)
	cmd := exec.Command(os.Args[0], helperArgs...)
	cmd.Env = append(os.Environ(), cliHelperEnvironment+"=1")
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
