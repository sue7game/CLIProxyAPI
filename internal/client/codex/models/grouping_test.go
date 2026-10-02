package models

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

func TestGroupingCodexCatalogNeverReadsOtherClientMetadata(t *testing.T) {
	r := registry.GetGlobalRegistry()
	const allowed, denied = "grouping-codex-public", "grouping-codex-private"
	public := []*registry.ModelInfo{
		{ID: "grouping-custom", DisplayName: "Public custom", Description: "Public description", ContextLength: 12345},
		{ID: "grouping-alias", MetadataModelID: "gpt-5.5", DisplayName: "Public alias", ExplicitInputModalities: true,
			SupportedInputModalities: []string{"text"}, ExplicitThinking: true, Thinking: &registry.ThinkingSupport{Levels: []string{"low"}}},
	}
	r.RegisterClient(allowed, "codex", public)
	r.RegisterClient(denied, "codex", []*registry.ModelInfo{
		{ID: "grouping-custom", DisplayName: "PRIVATE METADATA", Description: "PRIVATE METADATA", Type: "devin", ContextLength: 999999},
		{ID: "grouping-alias", MetadataModelID: "gpt-image-2", Type: registry.OpenAIImageModelType, Description: "PRIVATE METADATA"},
		{ID: "grouping-secret"},
	})
	t.Cleanup(func() { r.UnregisterClient(allowed); r.UnregisterClient(denied) })
	catalog := r.ModelsForClients("openai", []string{allowed})
	r.UnregisterClient(allowed)
	if info := registry.LookupModelInfo("grouping-custom"); info == nil || info.Description != "PRIVATE METADATA" {
		t.Fatal("fixture must expose unscoped private metadata")
	}
	response := BuildResponseForCredentialCatalog(catalog, false, "cpa")
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PRIVATE METADATA") || strings.Contains(string(encoded), "grouping-secret") || strings.Contains(string(encoded), "(Devin)") {
		t.Fatalf("scoped metadata leaked: %s", encoded)
	}
	entries := response["models"].([]map[string]any)
	if len(entries) != 2 {
		t.Fatalf("model count = %d", len(entries))
	}
	for _, entry := range entries {
		switch entry["slug"] {
		case "grouping-custom":
			if entry["description"] != "Public description" || entry["context_window"] != 12345 {
				t.Fatalf("custom metadata = %#v", entry)
			}
		case "grouping-alias":
			if entry["visibility"] == "hide" || len(entry["input_modalities"].([]any)) != 1 {
				t.Fatalf("alias used unscoped template/capabilities: %#v", entry)
			}
			levels := entry["supported_reasoning_levels"].([]any)
			if len(levels) != 1 || levels[0].(map[string]any)["effort"] != "low" {
				t.Fatalf("alias reasoning = %#v", levels)
			}
		}
	}
}

func TestGroupingCodexEmptyCatalogDoesNotFallback(t *testing.T) {
	response := BuildResponseForCredentialCatalog(registry.CredentialModelCatalog{}, false, "")
	if entries := response["models"].([]map[string]any); len(entries) != 0 {
		t.Fatalf("empty authorized catalog = %#v", entries)
	}
}
