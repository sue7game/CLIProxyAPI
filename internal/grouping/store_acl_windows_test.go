package grouping

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestStoreWindowsRejectsPublicACL(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := user.User.Sid.String()
	for _, test := range []struct {
		sddl string
		want bool
	}{
		{"O:" + owner + "D:(A;;FA;;;" + owner + ")", true},
		{"O:" + owner + "D:(A;;FA;;;SY)(A;;FA;;;BA)", true},
		{"O:" + owner + "D:(A;;FA;;;WD)", false},
		{"O:" + owner + "D:(A;;FR;;;BU)", false},
		{"O:" + owner + "D:NO_ACCESS_CONTROL", false},
	} {
		sd, err := windows.SecurityDescriptorFromString(test.sddl)
		if err != nil {
			t.Fatal(err)
		}
		if got := privatePolicyDescriptor(sd); got != test.want {
			t.Errorf("ACL privacy = %v, want %v", got, test.want)
		}
	}
}
