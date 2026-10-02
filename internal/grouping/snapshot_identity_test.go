package grouping

import (
	"errors"
	"testing"
)

func TestSnapshotIdentityChangesNeverResetGroup(t *testing.T) {
	s := NewSnapshot()
	g, _ := s.CreateGroup("Restricted")
	i := testIdentity(Credential, "old-fingerprint")
	i.GroupID = g.ID
	if err := s.Register(i); err != nil {
		t.Fatal(err)
	}
	changed := i
	changed.GroupID = AllGroups
	if err := s.Register(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("registration replaced an existing binding: %v", err)
	}
	if err := s.ReplaceIdentity(i.ID, "old-fingerprint", "new-fingerprint"); err != nil {
		t.Fatal(err)
	}
	got := s.Identities[i.ID]
	if got.GroupID != g.ID || got.Fingerprint != "new-fingerprint" || got.State != Active {
		t.Fatal("controlled replacement lost identity or group")
	}
	if err := s.SetIdentityState(i.ID, PendingRebind); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceIdentity(i.ID, "old-fingerprint", "third-fingerprint"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale replacement was accepted: %v", err)
	}
}

func TestSnapshotCloneDoesNotExposeState(t *testing.T) {
	s := NewSnapshot()
	i := testIdentity(Token, "fingerprint")
	if err := s.Register(i); err != nil {
		t.Fatal(err)
	}
	clone := s.Clone()
	delete(clone.Identities, i.ID)
	clone.Groups["invalid"] = Group{Name: "untrusted"}
	if len(s.Identities) != 1 || len(s.Groups) != 0 {
		t.Fatal("snapshot clone exposed mutable maps")
	}
}

func TestSnapshotRejectsUnknownSchemaAndReferences(t *testing.T) {
	s := NewSnapshot()
	s.SchemaVersion++
	if err := s.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown schema: %v", err)
	}
	s = NewSnapshot()
	i := testIdentity(Credential, "fingerprint")
	i.GroupID = "unknown"
	s.Identities[i.ID] = i
	if err := s.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown group: %v", err)
	}
}
