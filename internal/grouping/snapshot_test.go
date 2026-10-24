package grouping

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSnapshotGroupsAndBindings(t *testing.T) {
	s := NewSnapshot()
	group, err := s.CreateGroup("  Team A  ")
	if err != nil || group.Name != "Team A" {
		t.Fatalf("create group: %v", err)
	}
	if _, err := s.CreateGroup("team a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	credential := testIdentity(Credential, "same-fingerprint")
	duplicate := testIdentity(Credential, "same-fingerprint")
	if err := s.Register(credential); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(duplicate); err != nil {
		t.Fatal(err)
	}
	if err := s.Bind([]string{credential.ID}, group.ID); err != nil {
		t.Fatal(err)
	}
	if s.Identities[credential.ID].GroupID != group.ID || s.Identities[duplicate.ID].GroupID != AllGroups {
		t.Fatal("duplicate source records shared a binding")
	}
	if err := s.DeleteGroup(group.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("deleted a referenced group: %v", err)
	}
	if err := s.RenameGroup(group.ID, "Renamed"); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotBindingBatchIsAtomic(t *testing.T) {
	s := NewSnapshot()
	g, _ := s.CreateGroup("A")
	i := testIdentity(Credential, "fingerprint")
	if err := s.Register(i); err != nil {
		t.Fatal(err)
	}
	if err := s.Bind([]string{i.ID, uuid.NewString()}, g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown identity: %v", err)
	}
	if s.Identities[i.ID].GroupID != AllGroups {
		t.Fatal("failed batch changed earlier binding")
	}
}

func TestSnapshotReservedAndInvalidNames(t *testing.T) {
	s := NewSnapshot()
	for _, name := range []string{"", " ", "all", "ALL", "所有分组", "bad\nname"} {
		if _, err := s.CreateGroup(name); !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if err := s.DeleteGroup(AllGroups); !errors.Is(err, ErrInvalid) {
		t.Fatal("deleted all")
	}
	if err := s.RenameGroup(AllGroups, "Other"); !errors.Is(err, ErrInvalid) {
		t.Fatal("renamed all")
	}
}

func testIdentity(kind ObjectKind, fingerprint string) Identity {
	return Identity{Binding: Binding{ID: uuid.NewString(), Kind: kind, GroupID: AllGroups, State: Active}, Provider: "test", Fingerprint: fingerprint}
}
