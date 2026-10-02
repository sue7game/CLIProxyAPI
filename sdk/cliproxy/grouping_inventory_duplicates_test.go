package cliproxy

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestGroupingInventoryDuplicateReorderDisableAndDelete(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	first := groupingInventoryCredential(t, f)
	applyInventoryConfig(t, f, func(cfg *config.Config) {
		duplicate := cfg.CloneForRuntime().OpenAICompatibility[0]
		duplicate.APIKeyEntries[0].GroupingID = ""
		cfg.OpenAICompatibility = append(cfg.OpenAICompatibility, duplicate)
	})
	secondID := f.service.cfg.OpenAICompatibility[1].APIKeyEntries[0].GroupingID
	bindInventoryDuplicateGroups(t, f, first.Attributes["grouping_id"], secondID)
	f.activate(t)
	before := f.snapshot(t)
	applyInventoryConfig(t, f, func(cfg *config.Config) {
		cfg.OpenAICompatibility[0], cfg.OpenAICompatibility[1] = cfg.OpenAICompatibility[1], cfg.OpenAICompatibility[0]
	})
	assertInventoryActiveSourceSet(t, f, map[string]bool{first.Attributes["grouping_id"]: true, secondID: true})
	assertGroupingInventoryScheduling(t, f, first, false)
	applyInventoryConfig(t, f, func(cfg *config.Config) { cfg.OpenAICompatibility[0].Disabled = true })
	assertInventoryActiveSourceSet(t, f, map[string]bool{first.Attributes["grouping_id"]: true})
	assertGroupingInventoryScheduling(t, f, first, false)
	for id, original := range before.Identities {
		if f.snapshot(t).Identities[id] != original {
			t.Fatal("duplicate reorder or disable changed an identity or binding")
		}
	}
	applyInventoryConfig(t, f, func(cfg *config.Config) { cfg.OpenAICompatibility = cfg.OpenAICompatibility[1:] })
	assertInventoryActiveSourceSet(t, f, map[string]bool{first.Attributes["grouping_id"]: true})
	if f.snapshot(t).Identities[secondID].State != grouping.Tombstone {
		t.Fatal("deleting the disabled duplicate did not retire only its own identity")
	}
	assertGroupingInventoryScheduling(t, f, first, false)
}

func bindInventoryDuplicateGroups(t *testing.T, f *groupingIntegrationFixture, firstID, secondID string) {
	t.Helper()
	firstGroup, secondGroup := f.createGroup(t, "First record"), f.createGroup(t, "Second record")
	var tokenID string
	for id, identity := range f.snapshot(t).Identities {
		if identity.Kind == grouping.Token {
			tokenID = id
		}
	}
	f.bind(t, groupingapi.BindingRequest{TokenIDs: []string{tokenID}, CredentialIDs: []string{firstID}, GroupID: firstGroup})
	f.bind(t, groupingapi.BindingRequest{CredentialIDs: []string{secondID}, GroupID: secondGroup})
}

func assertInventoryActiveSourceSet(t *testing.T, f *groupingIntegrationFixture, want map[string]bool) {
	t.Helper()
	seen := make(map[string]bool)
	for _, auth := range f.service.coreManager.List() {
		if !coreauth.IsConfigAPIKeyAuth(auth) || auth.EffectiveDisabled() {
			continue
		}
		id := auth.Attributes["grouping_id"]
		if !want[id] || seen[id] {
			t.Fatal("runtime retained an obsolete or duplicate logical source")
		}
		seen[id] = true
	}
	if len(seen) != len(want) {
		t.Fatal("runtime lost an active independent source")
	}
}
