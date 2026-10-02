package registry

import (
	"reflect"
	"testing"
)

func TestGroupingCatalogUsesOnlyClientMetadataAndIgnoresCooldown(t *testing.T) {
	r := GetGlobalRegistry()
	const allowed, denied = "grouping-registry-allowed", "grouping-registry-denied"
	const shared, secret = "grouping-shared", "grouping-secret"
	r.RegisterClient(denied, "codex", []*ModelInfo{{ID: shared, DisplayName: "private"}, {ID: secret}})
	r.RegisterClient(allowed, "gemini", []*ModelInfo{{ID: shared, DisplayName: "public"}})
	t.Cleanup(func() { r.UnregisterClient(allowed); r.UnregisterClient(denied) })
	r.SetModelQuotaExceeded(allowed, shared)
	r.SuspendClientModel(allowed, shared, "quota")
	catalog := r.ModelsForClients("openai", []string{allowed, allowed})
	if len(catalog.Models) != 1 || catalog.Models[0]["id"] != shared || catalog.Models[0]["display_name"] != "public" {
		t.Fatalf("catalog = %#v", catalog.Models)
	}
	if len(catalog.Providers[shared]) != 1 || catalog.Providers[shared][0] != "gemini" {
		t.Fatalf("providers = %#v", catalog.Providers)
	}
	catalog.Models[0]["display_name"] = "mutated"
	if next := r.ModelsForClients("openai", []string{allowed}); next.Models[0]["display_name"] != "public" {
		t.Fatal("returned catalog aliases registry state")
	}
	if empty := r.ModelsForClients("openai", nil); len(empty.Models) != 0 {
		t.Fatal("empty authorized set returned global models")
	}
}

func TestGroupingCatalogUnionAndDetachedProviderMetadata(t *testing.T) {
	r := GetGlobalRegistry()
	const first, second, denied = "grouping-union-a", "grouping-union-b", "grouping-union-denied"
	const shared, other, secret = "grouping-union-shared", "grouping-union-other", "grouping-union-secret"
	noWebSearch := false
	r.RegisterClient(first, "codex", []*ModelInfo{{ID: shared, SupportedInputModalities: []string{"text"}, NativeCapabilities: &NativeCapabilities{WebSearch: &noWebSearch}}})
	r.RegisterClient(second, "gemini", []*ModelInfo{{ID: shared, DisplayName: "other route"}, {ID: other}})
	r.RegisterClient(denied, "claude", []*ModelInfo{{ID: secret}})
	t.Cleanup(func() { r.UnregisterClient(first); r.UnregisterClient(second); r.UnregisterClient(denied) })
	catalog := r.ModelsForClients("openai", []string{second, first, first, "missing"})
	if len(catalog.Models) != 2 || catalog.Infos[secret] != nil {
		t.Fatalf("union = %#v", catalog.Models)
	}
	if !reflect.DeepEqual(catalog.Providers[shared], []string{"codex", "gemini"}) {
		t.Fatalf("providers = %#v", catalog.Providers)
	}
	if value := catalog.WebSearch[shared]; value == nil || *value {
		t.Fatal("capability union was widened")
	}
	info := catalog.LookupModelInfo(shared, "codex")
	info.SupportedInputModalities[0] = "image"
	*info.NativeCapabilities.WebSearch = true
	if got := catalog.LookupModelInfo(shared, "codex"); got.SupportedInputModalities[0] != "text" || *got.NativeCapabilities.WebSearch {
		t.Fatal("returned provider metadata aliases the catalog")
	}
	if catalog.LookupModelInfo(shared, "claude") != nil || catalog.LookupModelInfo(secret) != nil {
		t.Fatal("scoped lookup fell back to global metadata")
	}
	infos := catalog.ModelInfos()
	infos[0].DisplayName = "mutated"
	if catalog.LookupModelInfo(infos[0].ID).DisplayName == "mutated" {
		t.Fatal("Grok metadata aliases the catalog")
	}
}
