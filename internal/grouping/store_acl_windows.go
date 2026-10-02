package grouping

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privatePolicyDirectory(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	return err == nil && privatePolicyDescriptor(sd)
}

func privatePolicyHandleAccess(file *os.File) bool {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	return err == nil && privatePolicyDescriptor(sd)
}

func privatePolicyDescriptor(sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd == nil || !sd.IsValid() {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || !trustedPolicySID(owner, user.User.Sid) {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || !privatePolicyACE(ace, user.User.Sid) {
			return false
		}
	}
	return true
}

func privatePolicyACE(ace *windows.ACCESS_ALLOWED_ACE, user *windows.SID) bool {
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
	return trustedPolicySID(sid, user)
}

func trustedPolicySID(sid, user *windows.SID) bool {
	return sid != nil && sid.IsValid() && (sid.Equals(user) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}
