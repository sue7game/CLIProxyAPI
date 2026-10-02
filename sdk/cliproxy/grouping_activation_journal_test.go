package cliproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestGroupingActivationJournalRecoverKnownStates(t *testing.T) {
	for _, mode := range []string{"uncommitted", "policy-only", "committed"} {
		for _, enabled := range []bool{true, false} {
			name := mode + "/enable"
			if !enabled {
				name = mode + "/disable"
			}
			t.Run(name, func(t *testing.T) {
				f := newGroupingIntegrationFixture(t)
				f.initialize(t)
				if !enabled {
					f.activate(t)
				}
				before := f.snapshot(t)
				change := stageGroupingActivationIntent(t, f, enabled)
				revision := before.Revision
				if mode != "uncommitted" {
					commitGroupingJournalRevision(t, f)
					revision++
				}
				if mode == "committed" {
					if err := writeGroupingSource(change); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.restart(t); err != nil {
					t.Fatalf("recoverable activation intent rejected: %v", err)
				}
				assertGroupingJournalRecovered(t, f, before, revision, enabled == (mode == "committed"))
			})
		}
	}
}

func stageGroupingActivationIntent(t *testing.T, f *groupingIntegrationFixture, enabled bool) groupingFileChange {
	t.Helper()
	g := f.service.grouping
	cfg := g.current.Load().CloneForRuntime()
	cfg.Grouping.Enabled = enabled
	before, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	change, err := prepareGroupingConfigWrite(f.path, before, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.prepareActivationIntent(f.snapshot(t).Revision, enabled, *change); err != nil {
		t.Fatal(err)
	}
	return *change
}

func commitGroupingJournalRevision(t *testing.T, f *groupingIntegrationFixture) {
	t.Helper()
	if _, err := f.service.grouping.store.Update(f.snapshot(t).Revision, func(*grouping.Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func assertGroupingJournalRecovered(t *testing.T, f *groupingIntegrationFixture, before grouping.Snapshot, revision uint64, enabled bool) {
	t.Helper()
	after := f.snapshot(t)
	if after.Revision != revision || !reflect.DeepEqual(before.Identities, after.Identities) || !reflect.DeepEqual(before.Groups, after.Groups) {
		t.Fatal("journal recovery changed bindings or used an unexpected revision")
	}
	if f.service.grouping.enabled.Load() != enabled || f.service.cfg.Grouping.Enabled != enabled {
		t.Fatal("recovery left the wrong effective activation state")
	}
	if _, err := os.Lstat(filepath.Join(f.service.grouping.path, "activation.pending")); !os.IsNotExist(err) {
		t.Fatalf("resolved activation journal was not removed: %v", err)
	}
	credential := f.credential(t)
	err := f.service.coreManager.AuthorizeCredentialUse(f.ctx, credential)
	if enabled == (err == nil) {
		t.Fatalf("recovered runtime enforcement disagrees with activation state: enabled=%t err=%v", enabled, err)
	}
}

func TestGroupingActivationJournalRejectsDamagedOrAmbiguousStates(t *testing.T) {
	for _, mode := range []string{"malformed", "signature", "config-edited", "config-before-policy", "revision-advanced", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			f := newGroupingIntegrationFixture(t)
			f.initialize(t)
			before := f.snapshot(t)
			change := stageGroupingActivationIntent(t, f, true)
			journalPath := filepath.Join(f.service.grouping.path, "activation.pending")
			corruptGroupingJournalState(t, f, change, journalPath, mode)
			if err := f.restart(t); err == nil {
				t.Fatal("damaged or ambiguous activation transaction was silently accepted")
			}
			if _, err := os.Lstat(journalPath); err != nil {
				t.Fatalf("unresolved journal was removed: %v", err)
			}
			if after, err := f.service.grouping.store.Snapshot(); err == nil && !reflect.DeepEqual(before.Identities, after.Identities) {
				t.Fatal("failed recovery reset registered identities")
			}
		})
	}
}

func corruptGroupingJournalState(t *testing.T, f *groupingIntegrationFixture, change groupingFileChange, path, mode string) {
	t.Helper()
	switch mode {
	case "malformed":
		writeGroupingJournalTestFile(t, path, []byte(`{"revision":`))
	case "signature":
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var intent groupingActivationIntent
		if err := json.Unmarshal(data, &intent); err != nil {
			t.Fatal(err)
		}
		intent.Signature = "invalid-test-signature"
		data, err = json.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		writeGroupingJournalTestFile(t, path, data)
	case "config-edited":
		writeGroupingJournalTestFile(t, f.path, append(change.before, []byte("\n# unrelated concurrent edit\n")...))
	case "config-before-policy":
		writeGroupingJournalTestFile(t, f.path, change.after)
	case "revision-advanced":
		commitGroupingJournalRevision(t, f)
		commitGroupingJournalRevision(t, f)
	case "symlink":
		target := filepath.Join(t.TempDir(), "pending-copy")
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
}

func writeGroupingJournalTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
