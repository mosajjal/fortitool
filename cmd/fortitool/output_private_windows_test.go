//go:build windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func assertPrivateDirectory(t *testing.T, name string) {
	t.Helper()
	assertPrivatePathACL(t, name, true)
}

func assertPrivateFile(t *testing.T, name string) {
	t.Helper()
	assertPrivatePathACL(t, name, false)
}

func assertPrivatePathACL(t *testing.T, name string, directory bool) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateHandle(windows.Handle(f.Fd()), user.User.Sid, directory); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPrivateStagingDACLIsInheritedAndSurvivesRename(t *testing.T) {
	parent := t.TempDir()
	final := filepath.Join(parent, "published")
	staged, err := newStagedOutputDir(final)
	if err != nil {
		t.Fatal(err)
	}
	defer staged.Cleanup()
	assertPrivateDirectory(t, staged.temp)
	nested := filepath.Join(staged.temp, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(nested, "secret")
	if err := os.WriteFile(child, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	assertInheritedSingleUserACL(t, nested, true)
	assertInheritedSingleUserACL(t, child, false)
	if err := staged.Commit(); err != nil {
		t.Fatal(err)
	}
	assertPrivateDirectory(t, final)
	assertInheritedSingleUserACL(t, filepath.Join(final, "nested"), true)
	assertInheritedSingleUserACL(t, filepath.Join(final, "nested", "secret"), false)
}

func TestWindowsPrivateFileDACLIsPreservedByHardLinkPublication(t *testing.T) {
	name := filepath.Join(t.TempDir(), "published")
	if err := writeNewFile(name, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertPrivateFile(t, name)
}

func TestWindowsPrivateOutputCollisionAndCleanup(t *testing.T) {
	parent := t.TempDir()
	name := filepath.Join(parent, "published")
	if err := os.WriteFile(name, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(name, []byte("secret"), 0o600); err == nil {
		t.Fatal("expected existing output to be rejected")
	}
	matches, err := filepath.Glob(filepath.Join(parent, ".published.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary outputs remain after collision: %v", matches)
	}
}

func TestWindowsUnsupportedACLFilesystemFailsClosed(t *testing.T) {
	parent := t.TempDir()
	name := filepath.Join(parent, "published")
	err := writeNewFile(name, []byte("secret"), 0o600)
	if err == nil {
		assertPrivateFile(t, name)
		return
	}
	if _, statErr := os.Lstat(name); !os.IsNotExist(statErr) {
		t.Fatalf("output exists after private ACL setup failed: %v", statErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(parent, ".published.tmp-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary plaintext remains after private ACL setup failed: %v", matches)
	}
	t.Skipf("filesystem did not preserve the required private ACL: %v", err)
}

func TestWindowsPrivateTempRetriesNameCollision(t *testing.T) {
	parent := t.TempDir()
	first := ".secret.tmp-0"
	if err := os.WriteFile(filepath.Join(parent, first), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	name, handle, err := createPrivateTempWithRandom(
		parent,
		".secret.tmp-",
		false,
		bytes.NewReader(append(make([]byte, 4), bytes.Repeat([]byte{1}, 4)...)),
	)
	runtime.UnlockOSThread()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(name)
	if filepath.Base(name) == first {
		t.Fatal("private temp creation reused an existing name")
	}
}

func TestWindowsPrivateTempSupportsLongParentPath(t *testing.T) {
	parent := t.TempDir()
	for len(parent) < 280 {
		parent = filepath.Join(parent, "long-parent-segment")
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := createPrivateTempFile(parent, ".secret.tmp-", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(name)
	assertPrivateFile(t, name)
}

func assertInheritedSingleUserACL(t *testing.T, name string, directory bool) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(f.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil {
		t.Fatal("inherited DACL is nil")
	}
	if dacl.AceCount != 1 {
		t.Fatalf("inherited DACL has %d entries, want 1", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	wantFlags := uint8(windows.INHERITED_ACE)
	if directory {
		wantFlags |= windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != wantFlags {
		t.Fatalf("child ACE type/flags = %d/%#x, want inherited allow", ace.Header.AceType, ace.Header.AceFlags)
	}
	if ace.Mask != windows.GENERIC_ALL && ace.Mask != privateFileAllAccess {
		t.Fatalf("child ACE access mask = %#x, want full access", ace.Mask)
	}
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.Equals(user.User.Sid) {
		t.Fatal("child DACL grants an identity other than the effective user")
	}
}
