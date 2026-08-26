//go:build windows

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const privateFileAllAccess windows.ACCESS_MASK = 0x001f01ff

func createPrivateTempDir(dir, pattern string) (string, func() error, func(), error) {
	runtime.LockOSThread()
	name, handle, err := createPrivateTempWithRandom(dir, pattern, true, rand.Reader)
	if err != nil {
		runtime.UnlockOSThread()
		return "", nil, nil, err
	}
	return name, func() error { return windows.CloseHandle(handle) }, runtime.UnlockOSThread, nil
}

func createPrivateTempFile(dir, pattern string, _ os.FileMode) (*os.File, error) {
	name, handle, err := createPrivateTemp(dir, pattern, false)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(handle), name)
	if f == nil {
		_ = windows.CloseHandle(handle)
		_ = os.Remove(name)
		return nil, fmt.Errorf("createtemp %s: invalid file handle", name)
	}
	return f, nil
}

func publishPrivateTempFile(f *os.File, temp, name string) error {
	if err := os.Link(temp, name); err != nil {
		_ = f.Close()
		return fmt.Errorf("publishing output file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func createPrivateTemp(dir, pattern string, directory bool) (string, windows.Handle, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return createPrivateTempWithRandom(dir, pattern, directory, rand.Reader)
}

func createPrivateTempWithRandom(dir, pattern string, directory bool, randomSource io.Reader) (string, windows.Handle, error) {
	prefix, suffix, err := splitTempPattern(pattern, directory)
	if err != nil {
		return "", windows.InvalidHandle, err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return "", windows.InvalidHandle, err
	}
	defer parent.Close()

	user, attributes, err := privateSecurityAttributes(directory)
	if err != nil {
		return "", windows.InvalidHandle, err
	}
	for range 10000 {
		random := make([]byte, 4)
		if _, err := io.ReadFull(randomSource, random); err != nil {
			return "", windows.InvalidHandle, fmt.Errorf("generating private temporary name: %w", err)
		}
		leaf := prefix + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(random)), 10) + suffix
		objectName, err := windows.NewNTUnicodeString(leaf)
		if err != nil {
			return "", windows.InvalidHandle, err
		}
		oa := &windows.OBJECT_ATTRIBUTES{
			Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
			RootDirectory:      windows.Handle(parent.Fd()),
			ObjectName:         objectName,
			Attributes:         windows.OBJ_CASE_INSENSITIVE,
			SecurityDescriptor: attributes.SecurityDescriptor,
		}
		options := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_NON_DIRECTORY_FILE)
		fileAttributes := uint32(windows.FILE_ATTRIBUTE_NORMAL)
		if directory {
			options = windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_DIRECTORY_FILE
		} else {
			options |= windows.FILE_OPEN_REPARSE_POINT
		}
		var handle windows.Handle
		var status windows.IO_STATUS_BLOCK
		err = windows.NtCreateFile(
			&handle,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE,
			oa,
			&status,
			nil,
			fileAttributes,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			windows.FILE_CREATE,
			options,
			0,
			0,
		)
		runtime.KeepAlive(parent)
		runtime.KeepAlive(attributes)
		if err == windows.STATUS_OBJECT_NAME_COLLISION {
			continue
		}
		name := filepath.Join(dir, leaf)
		if err != nil {
			return "", windows.InvalidHandle, &os.PathError{Op: tempOp(directory), Path: name, Err: err}
		}
		if err := verifyPrivateHandle(handle, user.User.Sid, directory); err != nil {
			_ = windows.CloseHandle(handle)
			_ = os.Remove(name)
			return "", windows.InvalidHandle, &os.PathError{Op: tempOp(directory), Path: name, Err: err}
		}
		return name, handle, nil
	}
	return "", windows.InvalidHandle, &os.PathError{Op: tempOp(directory), Path: filepath.Join(dir, pattern), Err: os.ErrExist}
}

func splitTempPattern(pattern string, directory bool) (string, string, error) {
	if strings.ContainsAny(pattern, `/\\`) {
		return "", "", &os.PathError{Op: tempOp(directory), Path: pattern, Err: windows.ERROR_INVALID_NAME}
	}
	if i := strings.LastIndexByte(pattern, '*'); i >= 0 {
		return pattern[:i], pattern[i+1:], nil
	}
	return pattern, "", nil
}

func privateSecurityAttributes(directory bool) (*windows.Tokenuser, *windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving effective Windows identity: %w", err)
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;" + flags + ";FA;;;" + sid + ")")
	if err != nil {
		return nil, nil, fmt.Errorf("constructing private Windows security descriptor: %w", err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	return user, attributes, nil
}

func verifyPrivateHandle(handle windows.Handle, user *windows.SID, directory bool) error {
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("reading Windows security descriptor: %w", err)
	}
	if descriptor == nil || !descriptor.IsValid() {
		return fmt.Errorf("invalid Windows security descriptor")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("reading Windows DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("Windows DACL is not protected")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("reading Windows owner: %w", err)
	}
	if owner == nil || !owner.Equals(user) {
		return fmt.Errorf("Windows owner does not match the effective user")
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("reading Windows DACL: %w", err)
	}
	if dacl == nil || defaulted || dacl.AceCount != 1 {
		return fmt.Errorf("Windows DACL is not an explicit single-user ACL")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return fmt.Errorf("reading Windows DACL entry: %w", err)
	}
	if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return fmt.Errorf("Windows DACL entry is not an allow entry")
	}
	wantFlags := uint8(0)
	if directory {
		wantFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	if ace.Header.AceFlags != wantFlags {
		return fmt.Errorf("Windows DACL inheritance flags are %#x, want %#x", ace.Header.AceFlags, wantFlags)
	}
	if ace.Mask != windows.GENERIC_ALL && ace.Mask != privateFileAllAccess {
		return fmt.Errorf("Windows DACL access mask is %#x, want full access", ace.Mask)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.Equals(user) {
		return fmt.Errorf("Windows DACL entry does not match the effective user")
	}
	return nil
}

func tempOp(directory bool) string {
	if directory {
		return "mkdirtemp"
	}
	return "createtemp"
}
