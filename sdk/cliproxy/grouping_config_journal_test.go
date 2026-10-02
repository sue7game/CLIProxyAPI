package cliproxy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func configJournalFixture(t *testing.T) (*groupingService, groupingFileChange, grouping.Snapshot, grouping.Snapshot) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	change := groupingFileChange{path: path, before: []byte("api-keys: [old-test-secret]\n"), after: []byte("api-keys: [new-test-secret]\n")}
	if err := os.WriteFile(path, change.before, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := grouping.InitializeStore(filepath.Join(dir, "policy"), grouping.NewSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	g := &groupingService{owner: &Service{configPath: path}, path: filepath.Join(dir, "policy"), store: store}
	t.Cleanup(func() {
		if err := g.store.Close(); err != nil {
			t.Error(err)
		}
	})
	fingerprint, err := store.Fingerprint("token:test", "old-test-secret")
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	before, err := store.Update(1, func(snapshot *grouping.Snapshot) error {
		group, err := snapshot.CreateGroup("Restricted")
		if err != nil {
			return err
		}
		return snapshot.Register(grouping.Identity{Binding: grouping.Binding{ID: id, Kind: grouping.Token, GroupID: group.ID, State: grouping.Active}, Provider: "test", Fingerprint: fingerprint})
	})
	if err != nil {
		t.Fatal(err)
	}
	after := before.Clone()
	identity := after.Identities[id]
	identity.Fingerprint, err = store.Fingerprint("token:test", "new-test-secret")
	if err != nil {
		t.Fatal(err)
	}
	after.Identities[id] = identity
	return g, change, before, after
}

func TestConfigJournalCommitPublishesBothFiles(t *testing.T) {
	g, change, before, after := configJournalFixture(t)
	result, err := g.commitSourceTransaction(change, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != before.Revision+2 || !sameSourcePolicy(result, after) {
		t.Fatal("commit lost policy, group, or revision")
	}
	data, err := os.ReadFile(change.path)
	if err != nil || !bytes.Equal(data, change.after) {
		t.Fatalf("configuration not committed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(g.path, "config.pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("committed journal was not removed")
	}
}

func TestConfigJournalRecoveryAtEveryCommitBoundary(t *testing.T) {
	for _, phase := range []string{"prepared", "staged-before", "staged-after", "final"} {
		t.Run(phase, func(t *testing.T) {
			g, change, before, after := configJournalFixture(t)
			intent, staged, err := g.prepareSourceIntent(change, before, after)
			if err != nil {
				t.Fatal(err)
			}
			if phase != "prepared" {
				if _, err := g.publishSourcePolicy(before.Revision, staged); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "staged-after" || phase == "final" {
				if err := writeGroupingSource(change); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "final" {
				if _, err := g.publishSourcePolicy(before.Revision+1, intent.After); err != nil {
					t.Fatal(err)
				}
			}
			reopenConfigJournalStore(t, g)
			if err := g.recoverSourceTransaction(); err != nil {
				t.Fatal(err)
			}
			want := before
			if phase == "staged-after" || phase == "final" {
				want = after
			}
			got, err := g.store.Snapshot()
			if err != nil || !sameSourcePolicy(got, want) {
				t.Fatalf("wrong recovered policy: %v", err)
			}
			if err := g.recoverSourceTransaction(); err != nil {
				t.Fatalf("recovery is not idempotent: %v", err)
			}
		})
	}
}

func TestConfigJournalStagesChangedAndDeletedIdentities(t *testing.T) {
	g, change, before, after := configJournalFixture(t)
	for id := range after.Identities {
		delete(after.Identities, id)
	}
	_, staged, err := g.prepareSourceIntent(change, before, after)
	if err != nil {
		t.Fatal(err)
	}
	for id, old := range before.Identities {
		got := staged.Identities[id]
		if got.State != grouping.PendingRebind || got.GroupID != old.GroupID || got.Fingerprint != old.Fingerprint {
			t.Fatal("deleted identity was not quarantined with its old group")
		}
	}
	data, err := os.ReadFile(filepath.Join(g.path, "config.pending"))
	if err != nil || bytes.Contains(data, []byte("test-secret")) {
		t.Fatalf("journal leaked a raw secret: %v", err)
	}
}

func TestConfigJournalUnknownDiskStateFailsClosed(t *testing.T) {
	g, change, before, after := configJournalFixture(t)
	if _, _, err := g.prepareSourceIntent(change, before, after); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(change.path, []byte("unknown configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := g.recoverSourceTransaction(); err != grouping.ErrUnavailable {
		t.Fatalf("unknown recovery did not return a safe error: %v", err)
	}
	if _, err := g.store.Snapshot(); !errors.Is(err, grouping.ErrUnavailable) {
		t.Fatal("unknown transaction left authorization enabled")
	}
}

func TestConfigJournalRejectsActivationConflictAndStaleBase(t *testing.T) {
	g, change, before, after := configJournalFixture(t)
	activation := filepath.Join(g.path, "activation.pending")
	if err := os.WriteFile(activation, []byte("pending"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := g.commitSourceTransaction(change, before, after); !errors.Is(err, grouping.ErrConflict) {
		t.Fatalf("overlapping journal accepted: %v", err)
	}
	if err := os.Remove(activation); err != nil {
		t.Fatal(err)
	}
	if _, err := g.store.Update(before.Revision, func(*grouping.Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := g.commitSourceTransaction(change, before, after); !errors.Is(err, grouping.ErrRevision) {
		t.Fatalf("stale transaction accepted: %v", err)
	}
}

func reopenConfigJournalStore(t *testing.T, g *groupingService) {
	t.Helper()
	if err := g.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := grouping.OpenStore(g.path)
	if err != nil {
		t.Fatal(err)
	}
	g.store = store
}
