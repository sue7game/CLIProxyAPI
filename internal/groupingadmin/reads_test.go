package groupingadmin

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestStatusAndSafeItems(t *testing.T) {
	f := newFixture(t, sourceRecord{"token", grouping.Token, "all", grouping.Active},
		sourceRecord{"pending", grouping.Credential, "A", grouping.PendingRebind},
		sourceRecord{"retired", grouping.Credential, "B", grouping.Tombstone})
	status, err := f.backend.Status(testContext())
	if err != nil || !status.Initialized || !status.Healthy || status.Enabled || status.PendingCount != 1 || status.Revision != 1 {
		t.Fatalf("unexpected status: %+v %v", status, err)
	}
	items, err := f.backend.Items(testContext(), groupingapi.KindCredential)
	if err != nil || len(items.Items) != 2 || items.Revision != status.Revision {
		t.Fatalf("unexpected items: %+v %v", items, err)
	}
	for _, item := range items.Items {
		if item.Kind != "credential" || item.Label != "test-provider "+item.ID[:8] {
			t.Fatalf("incorrect safe default item: %+v", item)
		}
	}
	data, err := json.Marshal(items)
	if err != nil || strings.Contains(string(data), "fingerprint") || strings.Contains(string(data), strings.Repeat("a", 64)) {
		t.Fatal("identity fingerprint leaked into listing")
	}
	if _, err := f.backend.Items(testContext(), "unknown"); !errors.Is(err, groupingapi.ErrConflict) {
		t.Fatalf("unknown kind was accepted: %v", err)
	}
	tokens, err := f.backend.Items(testContext(), groupingapi.KindToken)
	if err != nil || len(tokens.Items) != 1 || tokens.Items[0].ID != f.ids["token"] {
		t.Fatalf("kind filter failed: %+v %v", tokens, err)
	}
}

func TestCatalogIsLockedAndValidated(t *testing.T) {
	f := newFixture(t, sourceRecord{"token", grouping.Token, "all", grouping.Active})
	f.backend.options.Catalog = func() map[string]Label {
		if f.mutex.TryLock() {
			f.mutex.Unlock()
			t.Error("catalog read ran outside the shared transaction lock")
		}
		return map[string]Label{f.ids["token"]: {Label: "Team token", Source: "config"}}
	}
	items, err := f.backend.Items(testContext(), groupingapi.KindToken)
	if err != nil || items.Items[0].Label != "Team token" || items.Items[0].Source != "config" {
		t.Fatalf("catalog was not used: %+v %v", items, err)
	}
	for _, label := range []Label{{Label: "bad\nlabel"}, {Source: "bad\x00source"}, {Label: strings.Repeat("x", 257)}, {Source: strings.Repeat("x", 513)}, {Label: "\xff"}} {
		f.backend.options.Catalog = func() map[string]Label { return map[string]Label{f.ids["token"]: label} }
		items, err := f.backend.Items(testContext(), groupingapi.KindToken)
		if !errors.Is(err, groupingapi.ErrUnavailable) || len(items.Items) != 0 {
			t.Fatalf("invalid catalog was accepted: %+v %v", items, err)
		}
	}
}

func TestGroupsIncludeAllAndRemainSorted(t *testing.T) {
	f := newFixture(t)
	groups, err := f.backend.Groups(testContext())
	if err != nil || len(groups.Groups) != 4 || groups.Revision != 1 {
		t.Fatalf("unexpected groups: %+v %v", groups, err)
	}
	if groups.Groups[0].ID != "all" || !groups.Groups[0].System {
		t.Fatal("system wildcard group is missing")
	}
	for index, name := range []string{"A", "B", "C"} {
		if groups.Groups[index+1].Name != name || groups.Groups[index+1].System {
			t.Fatalf("unexpected concrete group: %+v", groups.Groups[index+1])
		}
	}
}

func TestMissingAndClosedStoresFailClosed(t *testing.T) {
	f := newFixture(t)
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	status, err := f.backend.Status(testContext())
	if err != nil || !status.Initialized || status.Healthy {
		t.Fatalf("closed store is not reported unhealthy: %+v %v", status, err)
	}
	if _, err := f.backend.Groups(testContext()); !errors.Is(err, groupingapi.ErrUnavailable) {
		t.Fatalf("closed store did not deny reads: %v", err)
	}
	f.backend.options.Store = func() *grouping.Store { return nil }
	status, err = f.backend.Status(testContext())
	if err != nil || status.Initialized || status.Healthy {
		t.Fatalf("missing store is healthy: %+v %v", status, err)
	}
	if _, err := f.backend.Items(testContext(), "token"); !errors.Is(err, groupingapi.ErrUnavailable) {
		t.Fatalf("missing store did not deny reads: %v", err)
	}
}

func TestPreviewDoesNotWriteAndCountsActualChanges(t *testing.T) {
	f := newFixture(t, sourceRecord{"t1", grouping.Token, "A", grouping.Active},
		sourceRecord{"t2", grouping.Token, "B", grouping.Active},
		sourceRecord{"c1", grouping.Credential, "B", grouping.Active})
	before, data := snapshotOf(t, f), policyBytes(t, f)
	result, err := f.backend.Preview(testContext(), groupingapi.BindingRequest{
		TokenIDs: []string{f.ids["t1"], f.ids["t2"]}, GroupID: f.groups["B"],
	})
	if err != nil || result.AffectedCount != 1 || result.Revision != before.Revision {
		t.Fatalf("preview failed: %+v %v", result, err)
	}
	assertUnchanged(t, f, before, data)
}

func TestRequiredOptions(t *testing.T) {
	options := Options{Mutex: &sync.Mutex{}, Store: func() *grouping.Store { return nil }, Enabled: func() bool { return false }}
	for _, field := range []string{"mutex", "store", "enabled"} {
		t.Run(field, func(t *testing.T) {
			invalid := options
			switch field {
			case "mutex":
				invalid.Mutex = nil
			case "store":
				invalid.Store = nil
			case "enabled":
				invalid.Enabled = nil
			}
			if backend, err := New(invalid); backend != nil || !errors.Is(err, groupingapi.ErrUnavailable) {
				t.Fatalf("invalid options were accepted: %v", err)
			}
		})
	}
}
