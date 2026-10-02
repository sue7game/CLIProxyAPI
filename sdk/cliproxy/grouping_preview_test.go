package cliproxy

import (
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

func TestGroupingPreviewCatalogUsesStableCredentialIDsAndRegisteredNames(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	f.initialize(t)
	auths := f.service.coreManager.List()
	for _, auth := range auths {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: "prefix/public-alias"}})
	}
	disabled := auths[0].Clone()
	disabled.Disabled = true
	if _, err := f.service.coreManager.Update(f.ctx, disabled); err != nil {
		t.Fatal(err)
	}
	g := f.service.grouping
	policy := f.snapshot(t)
	g.mu.Lock()
	catalog, err := g.previewModelCatalog(f.ctx, policy)
	g.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != len(auths)-1 {
		t.Fatalf("catalog size = %d", len(catalog))
	}
	for _, auth := range auths[1:] {
		if !reflect.DeepEqual(catalog[auth.Attributes["grouping_id"]], []string{"prefix/public-alias"}) {
			t.Fatal("preview lost source identity or used a different model namespace")
		}
	}
}

func TestGroupingPreviewCatalogRefusesMismatchedSource(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	f.initialize(t)
	policy := f.snapshot(t)
	for id, identity := range policy.Identities {
		identity.Fingerprint = "mismatched-source"
		policy.Identities[id] = identity
	}
	g := f.service.grouping
	g.mu.Lock()
	_, err := g.previewModelCatalog(f.ctx, policy)
	g.mu.Unlock()
	if err == nil {
		t.Fatal("preview trusted stale source identity")
	}
}
