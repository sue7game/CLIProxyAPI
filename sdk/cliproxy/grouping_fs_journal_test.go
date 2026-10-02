package cliproxy

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func TestGroupingFSJournalsUseExclusivePublication(t *testing.T) {
	for _, name := range []string{"activation.pending", "config.pending"} {
		t.Run(name, func(t *testing.T) {
			g := groupingFSJournalService(t)
			path := filepath.Join(g.path, name)
			data := []byte("existing-test-journal")
			if err := writeGroupingSource(groupingFileChange{path: path, after: data}); err != nil {
				t.Fatal(err)
			}
			var err error
			if name == "activation.pending" {
				err = g.prepareActivationIntent(1, true, groupingFileChange{before: []byte("before"), after: []byte("after")})
			} else {
				err = g.writeSourceIntent(groupingSourceIntent{})
			}
			if !errors.Is(err, grouping.ErrUnavailable) || !g.unavailable.Load() {
				t.Fatalf("conflicting journal publication did not fail closed: %v", err)
			}
			assertGroupingFSContent(t, path, data)
			if _, err := g.store.Snapshot(); !errors.Is(err, grouping.ErrUnavailable) {
				t.Fatal("failed journal publication left the policy store available")
			}
		})
	}
}

func TestGroupingFSJournalsPublishAndRetire(t *testing.T) {
	g := groupingFSJournalService(t)
	change := groupingFileChange{before: []byte("before"), after: []byte("after")}
	if err := g.prepareActivationIntent(1, true, change); err != nil {
		t.Fatal(err)
	}
	if err := g.finishActivationIntent(); err != nil {
		t.Fatal(err)
	}
	if err := g.writeSourceIntent(groupingSourceIntent{}); err != nil {
		t.Fatal(err)
	}
	if err := g.finishSourceIntent(); err != nil {
		t.Fatal(err)
	}
	assertGroupingFSOnlyEntries(t, g.path, ".writer.lock", "identity.key", "policy.json")
}

func groupingFSJournalService(t *testing.T) *groupingService {
	t.Helper()
	path := filepath.Join(groupingFSTestDir(t), "policy")
	store, err := grouping.InitializeStore(path, grouping.NewSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return &groupingService{path: path, store: store}
}
