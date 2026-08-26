//go:build linux && !race

package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ulikunitz/xz"
)

const (
	xzRSSFixtureEnv  = "FORTITOOL_XZ_RSS_FIXTURE"
	xzRSSDestEnv     = "FORTITOOL_XZ_RSS_DEST"
	xzRSSModeEnv     = "FORTITOOL_XZ_RSS_MODE"
	xzRSSLaunchMode  = "launch"
	xzRSSMeasureMode = "measure"
)

func TestExtractFortinetXZHighRatioStreamingRSS(t *testing.T) {
	if fixture := os.Getenv(xzRSSFixtureEnv); fixture != "" {
		dest := os.Getenv(xzRSSDestEnv)
		switch os.Getenv(xzRSSModeEnv) {
		case xzRSSLaunchMode:
			runXZStreamingRSSLauncher(t, fixture, dest)
		case xzRSSMeasureMode:
			runXZStreamingRSSHelper(t, fixture, dest)
		default:
			t.Fatal("streaming RSS helper mode is missing")
		}
		return
	}

	const payloadSize = int64(96 << 20)
	var compressed bytes.Buffer
	xw, err := (xz.WriterConfig{
		CheckSum: xz.SHA256,
		DictCap:  1 << 20,
	}).NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(xw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "high-ratio.bin",
		Mode:     0o644,
		Size:     payloadSize,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(tw, zeroReader{}, payloadSize); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}

	modified, _ := addFortinetXZPlaceholders(t, compressed.Bytes())
	if ratio := payloadSize / int64(len(modified)); ratio < 1000 {
		t.Fatalf("fixture compression ratio = %d:1, want at least 1000:1", ratio)
	}

	root := t.TempDir()
	fixture := filepath.Join(root, "high-ratio.tar.xz")
	if err := os.WriteFile(fixture, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "output")
	cmd := exec.Command(os.Args[0], "-test.run=^TestExtractFortinetXZHighRatioStreamingRSS$", "-test.v")
	cmd.Env = xzRSSEnvironment(xzRSSLaunchMode, fixture, dest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("streaming RSS helper failed: %v\n%s", err, output)
	}
	t.Logf("high-ratio helper:\n%s", output)
}

func runXZStreamingRSSLauncher(t *testing.T, fixture, dest string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestExtractFortinetXZHighRatioStreamingRSS$", "-test.v")
	cmd.Env = xzRSSEnvironment(xzRSSMeasureMode, fixture, dest)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("streaming RSS measurement failed: %v\n%s", err, output)
	}
	t.Logf("streaming RSS measurement:\n%s", output)
}

func xzRSSEnvironment(mode, fixture, dest string) []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, xzRSSModeEnv+"=") ||
			strings.HasPrefix(entry, xzRSSFixtureEnv+"=") ||
			strings.HasPrefix(entry, xzRSSDestEnv+"=") {
			continue
		}
		env = append(env, entry)
	}
	return append(env,
		xzRSSModeEnv+"="+mode,
		xzRSSFixtureEnv+"="+fixture,
		xzRSSDestEnv+"="+dest,
	)
}

func runXZStreamingRSSHelper(t *testing.T, fixture, dest string) {
	t.Helper()
	if fixture == "" || dest == "" {
		t.Fatal("streaming RSS helper paths are missing")
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExtractXZTar(data, dest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dest, "high-ratio.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 96<<20 {
		t.Fatalf("extracted size = %d, want %d", info.Size(), int64(96<<20))
	}

	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	const maxRSSKiB = int64(80 << 10)
	peakRSSKiB := int64(usage.Maxrss)
	if peakRSSKiB > maxRSSKiB {
		t.Fatalf("peak RSS = %d KiB, want at most %d KiB", peakRSSKiB, maxRSSKiB)
	}
	t.Logf("peak RSS = %d KiB", peakRSSKiB)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
