package cliproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func prepareAuthJournalFixture(t *testing.T, create bool) (*groupingAuthFixture, *groupingAuthSourcePlan, groupingSourceIntent, grouping.Snapshot) {
	t.Helper()
	f := newGroupingAuthFixture(t, true)
	var before []byte
	if !create {
		auth := f.apply(t, "source.json")
		f.restrict(t, auth)
		before = f.read(t, "source.json")
	}
	after, err := assignGroupingAuthFileID(before, []byte(`{"type":"codex","account_id":"new-account","access_token":"journal-only-test-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.g.planAuthSource(f.path("source.json"), before, after)
	if err != nil {
		t.Fatal(err)
	}
	intent, staged, err := f.g.prepareSourceIntent(plan.change, plan.before, plan.after)
	if err != nil {
		t.Fatal(err)
	}
	return f, plan, intent, staged
}

func TestGroupingSourceJournalAuthRecoveryAtEveryBoundary(t *testing.T) {
	for _, create := range []bool{false, true} {
		for _, phase := range []string{"prepared", "staged", "written", "committed"} {
			t.Run(map[bool]string{false: "replace-", true: "create-"}[create]+phase, func(t *testing.T) {
				f, plan, intent, staged := prepareAuthJournalFixture(t, create)
				if phase != "prepared" {
					if _, err := f.g.publishSourcePolicy(plan.before.Revision, staged); err != nil {
						t.Fatal(err)
					}
				}
				written := phase == "written" || phase == "committed"
				if written {
					if err := f.g.writeIntentSource(intent, plan.change); err != nil {
						t.Fatal(err)
					}
				}
				if phase == "committed" {
					if _, err := f.g.publishSourcePolicy(staged.Revision, intent.After); err != nil {
						t.Fatal(err)
					}
				}
				reopenConfigJournalStore(t, f.g)
				if err := f.g.recoverSourceTransaction(); err != nil {
					t.Fatal(err)
				}
				want := plan.before
				if written {
					want = plan.after
				}
				if got := f.snapshot(t); !sameSourcePolicy(got, want) {
					t.Fatal("recovery changed source groups or IDs")
				}
				if err := f.g.recoverSourceTransaction(); err != nil {
					t.Fatalf("recovery not idempotent: %v", err)
				}
			})
		}
	}
}

func TestGroupingSourceJournalUnknownOrSymlinkStateFailsClosed(t *testing.T) {
	for _, mutation := range []string{"unknown-bytes", "empty-file", "symlink", "directory-symlink"} {
		t.Run(mutation, func(t *testing.T) {
			f, plan, _, staged := prepareAuthJournalFixture(t, true)
			if _, err := f.g.publishSourcePolicy(plan.before.Revision, staged); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "unknown-bytes", "empty-file":
				data := []byte("not-the-signed-source")
				if mutation == "empty-file" {
					data = []byte{}
				}
				if err := os.WriteFile(plan.change.path, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := filepath.Join(t.TempDir(), "target.json")
				if err := os.WriteFile(other, plan.change.after, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, plan.change.path); err != nil {
					t.Fatal(err)
				}
			case "directory-symlink":
				dir := filepath.Dir(plan.change.path)
				moved := dir + "-moved"
				if err := os.Rename(dir, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, dir); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.g.recoverSourceTransaction(); !errors.Is(err, grouping.ErrUnavailable) {
				t.Fatalf("unrecognized state recovered: %v", err)
			}
			if _, err := f.g.store.Snapshot(); !errors.Is(err, grouping.ErrUnavailable) {
				t.Fatal("unknown recovery left usable policy")
			}
		})
	}
}

func TestGroupingSourceJournalSignatureCoversPathAndExistence(t *testing.T) {
	for _, field := range []string{"source_path", "before_exists", "source_kind"} {
		t.Run(field, func(t *testing.T) {
			f, _, intent, _ := prepareAuthJournalFixture(t, true)
			switch field {
			case "source_path":
				intent.SourcePath = f.path("transplanted.json")
			case "before_exists":
				intent.BeforeExists, intent.BeforeHash = true, groupingSourceDigest(nil)
			case "source_kind":
				intent.SourceKind = "config"
			}
			raw, err := json.Marshal(intent)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.g.path, "config.pending"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := f.g.recoverSourceTransaction(); !errors.Is(err, grouping.ErrUnavailable) {
				t.Fatal("unsigned journal edit accepted")
			}
		})
	}
}

func TestGroupingSourceJournalDoesNotUndoCommittedPolicy(t *testing.T) {
	f, plan, intent, staged := prepareAuthJournalFixture(t, false)
	if _, err := f.g.publishSourcePolicy(plan.before.Revision, staged); err != nil {
		t.Fatal(err)
	}
	if err := f.g.writeIntentSource(intent, plan.change); err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.publishSourcePolicy(staged.Revision, intent.After); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plan.change.path, plan.change.before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.g.recoverSourceTransaction(); !errors.Is(err, grouping.ErrUnavailable) {
		t.Fatal("replaying prior source rolled back committed policy")
	}
}

func TestGroupingSourceJournalExclusiveCreateDoesNotOverwrite(t *testing.T) {
	f, plan, intent, staged := prepareAuthJournalFixture(t, true)
	if _, err := f.g.publishSourcePolicy(plan.before.Revision, staged); err != nil {
		t.Fatal(err)
	}
	concurrent := []byte(`{"type":"codex","account_id":"concurrent"}`)
	if err := os.WriteFile(plan.change.path, concurrent, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.g.writeIntentSource(intent, plan.change); err == nil {
		t.Fatal("exclusive create overwrote another source")
	}
	if data := f.read(t, "source.json"); !bytes.Equal(data, concurrent) {
		t.Fatal("concurrent file overwritten")
	}
}

func TestGroupingSourceJournalCorruptPendingBlocksNewWritesAndAuthorization(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	if err := os.WriteFile(filepath.Join(f.g.path, "config.pending"), []byte(`{"unknown":"transaction"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.g.applyAuthFile(f.ctx, f.path("blocked.json"), []byte(`{"type":"codex","account_id":"blocked"}`)); !errors.Is(err, grouping.ErrUnavailable) {
		t.Fatalf("corrupt pending journal not treated as unavailable: %v", err)
	}
	if !f.g.unavailable.Load() {
		t.Fatal("unknown transaction did not close health gate")
	}
	if _, err := os.Stat(f.path("blocked.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("blocked mutation persisted a credential")
	}
}

func TestGroupingSourceJournalInfersAuthPendingIDs(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	after, err := assignGroupingAuthFileID(nil, []byte(`{"type":"codex","account_id":"source-id-test"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.g.planAuthSource(f.path("inferred.json"), nil, after)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.commitSourceTransaction(plan.change, plan.before, plan.after); err != nil {
		t.Fatalf("existing transaction signature did not accept an auth source: %v", err)
	}
	if !bytes.Equal(f.read(t, "inferred.json"), after) {
		t.Fatal("inferred-source transaction did not persist exact bytes")
	}
}
