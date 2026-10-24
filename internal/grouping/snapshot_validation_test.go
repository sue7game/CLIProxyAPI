package grouping

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSnapshotUnicodeNameUniquenessMatchesCRUD(t *testing.T) {
	snapshot := NewSnapshot()
	group, err := snapshot.CreateGroup("S")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.CreateGroup("ſ"); !errors.Is(err, ErrConflict) {
		t.Fatalf("equivalent name accepted by CRUD: %v", err)
	}
	group.ID, group.Name = uuid.NewString(), "ſ"
	snapshot.Groups[group.ID] = group
	if !errors.Is(snapshot.Validate(), ErrInvalid) {
		t.Fatal("Validate allowed a name rejected by CRUD")
	}
}

func TestSnapshotRejectsInvalidIdentityStrings(t *testing.T) {
	for _, value := range []string{"\xff", "bad\nvalue", " padded "} {
		for _, field := range []string{"provider", "fingerprint"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				snapshot := NewSnapshot()
				identity := testIdentity(Credential, "fingerprint")
				if field == "provider" {
					identity.Provider = value
				} else {
					identity.Fingerprint = value
				}
				if !errors.Is(snapshot.Register(identity), ErrInvalid) {
					t.Fatal("invalid identity input accepted")
				}
			})
		}
	}
}
