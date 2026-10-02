package registry

import (
	"reflect"
	"testing"
)

func TestModelIDsForClientsIsScopedSortedAndDetached(t *testing.T) {
	r := GetGlobalRegistry()
	const first, second = "preview-catalog-a", "preview-catalog-b"
	r.RegisterClient(first, "codex", []*ModelInfo{{ID: "prefix/z"}, {ID: "alias-a"}})
	r.RegisterClient(second, "claude", []*ModelInfo{{ID: "private-b"}})
	t.Cleanup(func() { r.UnregisterClient(first); r.UnregisterClient(second) })
	r.SetModelQuotaExceeded(first, "alias-a")
	got := r.ModelIDsForClients([]string{first, "missing", first})
	if len(got) != 2 || !reflect.DeepEqual(got[first], []string{"alias-a", "prefix/z"}) || len(got["missing"]) != 0 {
		t.Fatalf("unexpected client snapshot: %#v", got)
	}
	got[first][0] = "changed"
	delete(got, first)
	if next := r.ModelIDsForClients([]string{first}); !reflect.DeepEqual(next[first], []string{"alias-a", "prefix/z"}) {
		t.Fatal("returned catalog aliases registry state")
	}
}
