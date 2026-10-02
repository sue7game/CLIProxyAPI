package groupingadmin

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

type sourceRecord struct {
	name  string
	kind  grouping.ObjectKind
	group string
	state grouping.RegistrationState
}

type fixture struct {
	backend       *Backend
	store         *grouping.Store
	mutex         sync.Mutex
	dir           string
	groups        map[string]string
	ids           map[string]string
	enabled       bool
	notifications atomic.Int64
}

func newFixture(t *testing.T, records ...sourceRecord) *fixture {
	t.Helper()
	f := &fixture{dir: filepath.Join(t.TempDir(), "policy"), groups: map[string]string{"all": "all"}, ids: map[string]string{}}
	snapshot := grouping.NewSnapshot()
	for _, name := range []string{"A", "B", "C"} {
		group, err := snapshot.CreateGroup(name)
		if err != nil {
			t.Fatal(err)
		}
		f.groups[name] = group.ID
	}
	for _, record := range records {
		state := record.state
		if state == "" {
			state = grouping.Active
		}
		id := uuid.NewString()
		identity := grouping.Identity{Binding: grouping.Binding{ID: id, Kind: record.kind, GroupID: f.groups[record.group], State: state},
			Provider: "test-provider", Fingerprint: strings.Repeat("a", 64)}
		if err := snapshot.Register(identity); err != nil {
			t.Fatal(err)
		}
		f.ids[record.name] = id
	}
	var err error
	f.store, err = grouping.InitializeStore(f.dir, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.store.Close(); err != nil {
			t.Error(err)
		}
	})
	f.backend, err = New(Options{Mutex: &f.mutex, Store: func() *grouping.Store { return f.store },
		Enabled: func() bool { return f.enabled }, OnPolicyChanged: func() { f.notifications.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func snapshotOf(t *testing.T, f *fixture) grouping.Snapshot {
	t.Helper()
	snapshot, err := f.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func policyBytes(t *testing.T, f *fixture) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertUnchanged(t *testing.T, f *fixture, before grouping.Snapshot, data []byte) {
	t.Helper()
	if !reflect.DeepEqual(before, snapshotOf(t, f)) || !reflect.DeepEqual(data, policyBytes(t, f)) {
		t.Fatal("failed operation changed the in-memory or persisted policy")
	}
	if f.notifications.Load() != 0 {
		t.Fatal("failed operation reported a policy change")
	}
}

func testContext() context.Context {
	return context.Background()
}
