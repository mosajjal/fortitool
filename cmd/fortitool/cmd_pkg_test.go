package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var (
	testOIDSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	testOIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	testOIDSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	testOIDRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type testAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func TestCmdPkgInspectArgumentOrderAndArity(t *testing.T) {
	payloadPath, signaturePath := writePackageFixture(t, []bool{true})

	if _, _, err := captureCommandOutput(t, func() error {
		return cmdPkgInspect([]string{"--content", payloadPath, signaturePath})
	}); err != nil {
		t.Fatalf("flags-first inspect failed: %v", err)
	}

	if _, _, err := captureCommandOutput(t, func() error {
		return cmdPkgInspect([]string{signaturePath, "--content", payloadPath})
	}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("post-positional flag error = %v, want usage error", err)
	}

	if _, _, err := captureCommandOutput(t, func() error {
		return cmdPkgInspect([]string{signaturePath, "extra.x"})
	}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("extra positional error = %v, want usage error", err)
	}
}

func TestCmdPkgInspectRejectsExplicitEmptyContent(t *testing.T) {
	_, signaturePath := writePackageFixture(t, []bool{true})
	tests := []struct {
		name string
		args []string
	}{
		{name: "equals form", args: []string{"--content=", signaturePath}},
		{name: "separate argument", args: []string{"--content", "", signaturePath}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, stderr, err := captureCommandOutput(t, func() error {
				return cmdPkgInspect(test.args)
			})
			if err == nil || !strings.Contains(err.Error(), "--content requires a non-empty path") {
				t.Fatalf("cmdPkgInspect error = %v, want explicit empty content error", err)
			}
			if got := commandExitCode(err); got != 2 {
				t.Fatalf("commandExitCode(error) = %d, want 2", got)
			}
			if !strings.Contains(stderr, "fortitool pkg inspect [--content <payload>] <sig.x>") {
				t.Fatalf("stderr does not contain inspect usage:\n%s", stderr)
			}
		})
	}
}

func TestCmdPkgInspectWithoutContentRemainsInspectionOnly(t *testing.T) {
	_, signaturePath := writePackageFixture(t, []bool{true})
	stdout, _, err := captureCommandOutput(t, func() error {
		return cmdPkgInspect([]string{signaturePath})
	})
	if err != nil {
		t.Fatalf("cmdPkgInspect: %v", err)
	}
	if !strings.Contains(stdout, "pass --content <payload> to verify") {
		t.Fatalf("stdout does not describe optional verification:\n%s", stdout)
	}
	if strings.Contains(stdout, "cryptographic integrity:") {
		t.Fatalf("inspection-only output unexpectedly contains a verification result:\n%s", stdout)
	}
}

func TestCmdPkgInspectVerificationPolicy(t *testing.T) {
	tests := []struct {
		name       string
		signers    []bool
		wantError  string
		wantOutput string
	}{
		{name: "no signers", signers: nil, wantError: "no SignerInfo entries", wantOutput: "cryptographic integrity: FAILED"},
		{name: "all invalid", signers: []bool{false, false}, wantError: "2 of 2 SignerInfo entries invalid", wantOutput: "signer 1"},
		{name: "mixed signers", signers: []bool{true, false}, wantError: "1 of 2 SignerInfo entries invalid", wantOutput: "signer 0"},
		{name: "all valid", signers: []bool{true, true}, wantOutput: "cryptographic integrity: PASSED (2 of 2 signers valid)"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payloadPath, signaturePath := writePackageFixture(t, test.signers)
			stdout, _, err := captureCommandOutput(t, func() error {
				return cmdPkgInspect([]string{"--content", payloadPath, signaturePath})
			})
			if test.wantError == "" && err != nil {
				t.Fatalf("cmdPkgInspect: %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("cmdPkgInspect error = %v, want substring %q", err, test.wantError)
			}
			if !strings.Contains(stdout, test.wantOutput) {
				t.Fatalf("stdout does not contain %q:\n%s", test.wantOutput, stdout)
			}
			if !strings.Contains(stdout, "trust chain: NOT VALIDATED") {
				t.Fatalf("stdout does not distinguish trust-chain validation:\n%s", stdout)
			}
		})
	}
}

func TestCmdPkgScanRegularFilesAndSuggestion(t *testing.T) {
	root := t.TempDir()
	payload := []byte("synthetic package payload")
	certDER, privateKey := buildPackageTestCertificate(t)
	signature := buildPackageSignedData(t, certDER, privateKey, payload, []bool{true})
	writeTestFile(t, filepath.Join(root, "component"), payload)
	writeTestFile(t, filepath.Join(root, "component.x"), signature)
	writeTestFile(t, filepath.Join(root, "program"), []byte{0x7f, 'E', 'L', 'F', 1, 2, 3})

	stdout, _, err := captureCommandOutput(t, func() error { return cmdPkgScan([]string{root}) })
	if err != nil {
		t.Fatalf("cmdPkgScan: %v", err)
	}
	for _, want := range []string{
		"Scanned 3 regular files",
		"== ELF (1) ==",
		"== PKCS#7 SignedData (1) ==",
		pkgInspectSuggestion(runtime.GOOS, filepath.Join(root, "component"), filepath.Join(root, "component.x")),
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout does not contain %q:\n%s", want, stdout)
		}
	}
}

func TestCmdPkgScanOmitsSuggestionForControlPaths(t *testing.T) {
	root := t.TempDir()
	payloadName := "component $(echo unsafe) \x1b\u202e'payload"
	if runtime.GOOS == "windows" {
		payloadName = "component $(echo unsafe) \u202e'payload"
	}
	signatureName := payloadName + ".x"
	payload := []byte("synthetic package payload")
	certDER, privateKey := buildPackageTestCertificate(t)
	signature := buildPackageSignedData(t, certDER, privateKey, payload, []bool{true})
	writeTestFile(t, filepath.Join(root, payloadName), payload)
	writeTestFile(t, filepath.Join(root, signatureName), signature)

	stdout, _, err := captureCommandOutput(t, func() error { return cmdPkgScan([]string{root}) })
	if err != nil {
		t.Fatalf("cmdPkgScan: %v", err)
	}
	if strings.Contains(stdout, "\x1b") {
		t.Fatalf("stdout contains a literal escape byte:\n%s", stdout)
	}
	if strings.Contains(stdout, "\u202e") {
		t.Fatalf("stdout contains a literal bidi override:\n%s", stdout)
	}
	if strings.Contains(stdout, "--content") {
		t.Fatalf("stdout contains a copyable command for a control-bearing path:\n%s", stdout)
	}
	if !strings.Contains(stdout, "no copyable command") {
		t.Fatalf("stdout does not explain why the command was omitted:\n%s", stdout)
	}
}

func TestCmdPkgScanHandlesPrintableShellMetacharacters(t *testing.T) {
	root := t.TempDir()
	payloadName := "component $(echo unsafe) 'payload"
	signatureName := payloadName + ".x"
	payload := []byte("synthetic package payload")
	certDER, privateKey := buildPackageTestCertificate(t)
	signature := buildPackageSignedData(t, certDER, privateKey, payload, []bool{true})
	writeTestFile(t, filepath.Join(root, payloadName), payload)
	writeTestFile(t, filepath.Join(root, signatureName), signature)

	stdout, _, err := captureCommandOutput(t, func() error { return cmdPkgScan([]string{root}) })
	if err != nil {
		t.Fatalf("cmdPkgScan: %v", err)
	}
	contentPath := filepath.Join(root, payloadName)
	signaturePath := filepath.Join(root, signatureName)
	want := pkgInspectSuggestion(runtime.GOOS, contentPath, signaturePath)
	if !strings.Contains(stdout, want) {
		t.Fatalf("stdout does not contain safely quoted rooted suggestion %q:\n%s", want, stdout)
	}
}

func TestPkgInspectSuggestionOmitsShellSyntaxOnWindows(t *testing.T) {
	content := `component & whoami | echo %PATH% ^ !`
	signature := content + `.x`
	suggestion := pkgInspectSuggestion("windows", content, signature)
	if strings.Contains(suggestion, content) || strings.Contains(suggestion, signature) {
		t.Fatalf("Windows suggestion contains attacker-controlled shell text: %s", suggestion)
	}
	if strings.Contains(suggestion, "--content") {
		t.Fatalf("Windows suggestion is unexpectedly copyable shell syntax: %s", suggestion)
	}
	if !strings.Contains(suggestion, "no copyable command") {
		t.Fatalf("Windows suggestion does not explain the safety boundary: %s", suggestion)
	}
}

func TestCmdPkgScanRejectsExtraArguments(t *testing.T) {
	if _, _, err := captureCommandOutput(t, func() error {
		return cmdPkgScan([]string{t.TempDir(), "extra"})
	}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("extra positional error = %v, want usage error", err)
	}
}

func TestScanPackageFilesPropagatesWalkError(t *testing.T) {
	want := fs.ErrPermission
	_, err := scanPackageFiles("synthetic-root", func(root string, visit fs.WalkDirFunc) error {
		return visit(filepath.Join(root, "unreadable"), nil, want)
	})
	if !errors.Is(err, want) {
		t.Fatalf("scanPackageFiles error = %v, want %v", err, want)
	}
}

func TestScanPackageFilesReportsSpecialEntries(t *testing.T) {
	root := "synthetic-root"
	device := fakeDirEntry{info: fakeFileInfo{name: "device", mode: os.ModeDevice}}
	scan, err := scanPackageFiles(root, func(_ string, visit fs.WalkDirFunc) error {
		return visit(filepath.Join(root, device.Name()), device, nil)
	})
	if err != nil {
		t.Fatalf("scanPackageFiles: %v", err)
	}
	if scan.regularFiles != 0 || scan.symlinks != 0 || scan.specialFiles != 1 {
		t.Fatalf("scan counts = regular %d, symlinks %d, special %d", scan.regularFiles, scan.symlinks, scan.specialFiles)
	}
	entries := scan.buckets[specialKind]
	if len(entries) != 1 || entries[0].path != "device" {
		t.Fatalf("special entries = %+v", entries)
	}
}

func TestClassifyReaderIsBoundedAndPropagatesErrors(t *testing.T) {
	reader := &fullReader{}
	if _, err := classifyReader(reader); err != nil {
		t.Fatalf("classifyReader: %v", err)
	}
	if reader.bytesRead != classificationPrefixSize {
		t.Fatalf("read %d bytes, want %d", reader.bytesRead, classificationPrefixSize)
	}

	want := errors.New("synthetic read failure")
	if _, err := classifyReader(errorReader{err: want}); !errors.Is(err, want) {
		t.Fatalf("classifyReader error = %v, want %v", err, want)
	}
}

type fullReader struct {
	bytesRead int
}

func (r *fullReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i)
	}
	r.bytesRead += len(p)
	return len(p), nil
}

type errorReader struct {
	err error
}

type fakeDirEntry struct {
	info fakeFileInfo
}

func (entry fakeDirEntry) Name() string               { return entry.info.Name() }
func (entry fakeDirEntry) IsDir() bool                { return entry.info.IsDir() }
func (entry fakeDirEntry) Type() fs.FileMode          { return entry.info.Mode().Type() }
func (entry fakeDirEntry) Info() (fs.FileInfo, error) { return entry.info, nil }

type fakeFileInfo struct {
	name string
	mode fs.FileMode
}

func (info fakeFileInfo) Name() string       { return info.name }
func (info fakeFileInfo) Size() int64        { return 0 }
func (info fakeFileInfo) Mode() fs.FileMode  { return info.mode }
func (info fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (info fakeFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info fakeFileInfo) Sys() any           { return nil }

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func writePackageFixture(t *testing.T, signers []bool) (string, string) {
	t.Helper()
	payload := []byte("fortitool synthetic payload for package verification")
	certDER, privateKey := buildPackageTestCertificate(t)
	signature := buildPackageSignedData(t, certDER, privateKey, payload, signers)
	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "payload")
	signaturePath := filepath.Join(dir, "payload.x")
	writeTestFile(t, payloadPath, payload)
	writeTestFile(t, signaturePath, signature)
	return payloadPath, signaturePath
}

func buildPackageTestCertificate(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(0xC011),
		Subject:      pkix.Name{CommonName: "fortitool-package-test-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return certDER, privateKey
}

func buildPackageSignedData(t *testing.T, certDER []byte, privateKey *rsa.PrivateKey, content []byte, validSigners []bool) []byte {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	digestAlgorithms := testDERTLV(0x31, marshalPackageASN1(t, testAlgorithmIdentifier{Algorithm: testOIDSHA256}))
	innerContentInfo := marshalPackageASN1(t, struct{ ContentType asn1.ObjectIdentifier }{testOIDData})
	certificates := testDERTLV(0xa0, certDER)
	issuerAndSerial := testDERTLV(0x30, append(cert.RawIssuer, marshalPackageASN1(t, cert.SerialNumber)...))
	digestAlgorithm := marshalPackageASN1(t, testAlgorithmIdentifier{Algorithm: testOIDSHA256})
	signatureAlgorithm := marshalPackageASN1(t, testAlgorithmIdentifier{
		Algorithm:  testOIDRSAEncryption,
		Parameters: asn1.RawValue{Tag: asn1.TagNull},
	})

	var signerInfosBody []byte
	for _, valid := range validSigners {
		signedContent := content
		if !valid {
			signedContent = append(append([]byte{}, content...), 'X')
		}
		digest := sha256.Sum256(signedContent)
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		signerInfoBody := marshalPackageASN1(t, 1)
		signerInfoBody = append(signerInfoBody, issuerAndSerial...)
		signerInfoBody = append(signerInfoBody, digestAlgorithm...)
		signerInfoBody = append(signerInfoBody, signatureAlgorithm...)
		signerInfoBody = append(signerInfoBody, marshalPackageASN1(t, signature)...)
		signerInfosBody = append(signerInfosBody, testDERTLV(0x30, signerInfoBody)...)
	}

	signedDataBody := marshalPackageASN1(t, 1)
	signedDataBody = append(signedDataBody, digestAlgorithms...)
	signedDataBody = append(signedDataBody, innerContentInfo...)
	signedDataBody = append(signedDataBody, certificates...)
	signedDataBody = append(signedDataBody, testDERTLV(0x31, signerInfosBody)...)
	signedData := testDERTLV(0x30, signedDataBody)
	contentInfoBody := append(marshalPackageASN1(t, testOIDSignedData), testDERTLV(0xa0, signedData)...)
	return testDERTLV(0x30, contentInfoBody)
}

func marshalPackageASN1(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return encoded
}

func testDERTLV(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, testDERLength(len(content))...), content...)
}

func testDERLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	var encoded []byte
	for remaining := length; remaining > 0; remaining >>= 8 {
		encoded = append([]byte{byte(remaining)}, encoded...)
	}
	return append([]byte{0x80 | byte(len(encoded))}, encoded...)
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func captureCommandOutput(t *testing.T, run func() error) (string, string, error) {
	t.Helper()
	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		stdoutReader.Close()
		stdoutWriter.Close()
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter

	stdoutResult := make(chan []byte, 1)
	stderrResult := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(stdoutReader)
		stdoutResult <- data
	}()
	go func() {
		data, _ := io.ReadAll(stderrReader)
		stderrResult <- data
	}()

	runErr := run()
	stdoutWriter.Close()
	stderrWriter.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	stdout := <-stdoutResult
	stderr := <-stderrResult
	stdoutReader.Close()
	stderrReader.Close()
	return string(stdout), string(stderr), runErr
}
