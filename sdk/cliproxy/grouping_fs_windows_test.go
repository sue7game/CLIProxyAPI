package cliproxy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func protectGroupingFSTestDir(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	setGroupingFSTestDACL(t, path, "D:P(A;OICI;FA;;;"+user.User.Sid.String()+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
}

func setGroupingFSTestDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestGroupingFSWindowsPrivateSourceACL(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := user.User.Sid.String()
	for _, test := range []struct {
		name string
		dacl string
		want bool
	}{
		{"owner", "D:(A;;FA;;;" + owner + ")", true},
		{"system-admin", "D:(A;;FA;;;SY)(A;;FA;;;BA)", true},
		{"public-read", "D:(A;;FR;;;WD)", false},
		{"users-read", "D:(A;;FR;;;BU)", false},
		{"null-dacl", "D:NO_ACCESS_CONTROL", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString("O:" + owner + test.dacl)
			if err != nil {
				t.Fatal(err)
			}
			if got := privateGroupingSourceDescriptor(sd); got != test.want {
				t.Fatalf("source ACL privacy = %t, want %t", got, test.want)
			}
		})
	}
	if privateGroupingSourceDescriptor(nil) {
		t.Fatal("missing security descriptor accepted")
	}
}

func TestGroupingFSWindowsPublicTempRejectedBeforeWrite(t *testing.T) {
	dir := groupingFSTestDir(t)
	file, err := os.CreateTemp(dir, ".test-public-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	setGroupingFSTestDACL(t, file.Name(), "D:P(A;;FA;;;"+user.User.Sid.String()+")(A;;FR;;;WD)")
	if err := writeGroupingTemp(file, []byte("never-write-this-test-source")); err == nil {
		t.Fatal("public temporary source was accepted")
	}
	assertGroupingFSContent(t, file.Name(), nil)
}

func TestGroupingFSWindowsMoveFailurePreservesFiles(t *testing.T) {
	dir := groupingFSTestDir(t)
	target := filepath.Join(dir, "source.json")
	if err := writeGroupingSource(groupingFileChange{path: target, after: []byte("existing")}); err != nil {
		t.Fatal(err)
	}
	source, err := prepareGroupingSourceTemp(target, []byte("replacement"))
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Error(err)
		}
	}()
	if err := replaceGroupingFile(source, target); err == nil {
		t.Fatal("sharing violation was silently accepted")
	}
	assertGroupingFSContent(t, target, []byte("existing"))
	assertGroupingFSContent(t, source, []byte("replacement"))
}

func TestGroupingFSWindowsDirectorySyncCannotClaimDurability(t *testing.T) {
	if err := syncGroupingDirectory(groupingFSTestDir(t)); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("standalone directory sync returned %v, want unsupported", err)
	}
}
