package cliproxy

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func secureGroupingTemp(file *os.File) error {
	// Chmod(0600) does not restrict a Windows DACL. Check inherited access before
	// any source bytes are written, matching the policy store's private ACL rule.
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !privateGroupingSourceDescriptor(sd) {
		return fmt.Errorf("grouping: source temporary file requires a private Windows ACL")
	}
	return nil
}

func privateGroupingSourceDescriptor(sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd == nil || !sd.IsValid() {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || !trustedGroupingSourceSID(owner, user.User.Sid) {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || !privateGroupingSourceACE(ace, user.User.Sid) {
			return false
		}
	}
	return true
}

func privateGroupingSourceACE(ace *windows.ACCESS_ALLOWED_ACE, user *windows.SID) bool {
	if ace == nil {
		return false
	}
	if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
		return true
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return false
	}
	if ace.Mask == 0 {
		return true
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	return trustedGroupingSourceSID(sid, user)
}

func trustedGroupingSourceSID(sid, user *windows.SID) bool {
	return sid != nil && sid.IsValid() && (sid.Equals(user) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}
