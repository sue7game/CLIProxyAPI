package synthesizer

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func groupingSynthesisConfig() *config.Config {
	return &config.Config{
		Grouping:           config.GroupingConfig{Enabled: true},
		GeminiKey:          []config.GeminiKey{{APIKey: "same"}, {APIKey: "same"}},
		InteractionsKey:    []config.GeminiKey{{APIKey: "same"}, {APIKey: "same"}},
		ClaudeKey:          []config.ClaudeKey{{APIKey: "same"}, {APIKey: "same"}},
		CodexKey:           []config.CodexKey{{APIKey: "same"}, {APIKey: "same"}},
		XAIKey:             []config.XAIKey{{APIKey: "same"}, {APIKey: "same"}},
		MetaKey:            []config.MetaKey{{APIKey: "same"}, {APIKey: "same"}},
		VertexCompatAPIKey: []config.VertexCompatKey{{APIKey: "same"}, {APIKey: "same"}},
		OpenAICompatibility: []config.OpenAICompatibility{
			{Name: "no-key"}, {Name: "no-key"},
			{Name: "keys", APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "same"}, {APIKey: "same"}}},
		},
	}
}

func TestGroupingSynthesisDuplicateRecordsRemainIndependent(t *testing.T) {
	cfg := groupingSynthesisConfig()
	if _, err := config.EnsureGroupingCredentialIDs(cfg); err != nil {
		t.Fatal(err)
	}
	for _, generator := range []*StableIDGenerator{nil, NewStableIDGenerator()} {
		auths, err := NewConfigSynthesizer().Synthesize(&SynthesisContext{Config: cfg, IDGenerator: generator})
		if err != nil {
			t.Fatal(err)
		}
		if len(auths) != 18 {
			t.Fatalf("got %d records, want 18", len(auths))
		}
		ids, permanent := map[string]bool{}, map[string]bool{}
		for _, auth := range auths {
			id := auth.Attributes["grouping_id"]
			if ids[auth.ID] || id == "" || permanent[id] {
				t.Fatal("duplicate or missing identity")
			}
			ids[auth.ID], permanent[id] = true, true
		}
	}
}

func TestGroupingSynthesisRetainsLegacyRuntimeIDs(t *testing.T) {
	cfg := groupingSynthesisConfig()
	cfg.Grouping.Enabled = false
	before, err := NewConfigSynthesizer().Synthesize(&SynthesisContext{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = config.EnsureGroupingCredentialIDs(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Grouping.Enabled = true
	after, err := NewConfigSynthesizer().Synthesize(&SynthesisContext{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	for i := range before {
		if before[i].ID != after[i].ID {
			t.Fatal("adding identity changed runtime ID")
		}
	}
}

func TestGroupingSynthesisRoutingChangesRetainPermanentIDs(t *testing.T) {
	cfg := groupingSynthesisConfig()
	if _, err := config.EnsureGroupingCredentialIDs(cfg); err != nil {
		t.Fatal(err)
	}
	id := cfg.GeminiKey[0].GroupingID
	cfg.GeminiKey[0], cfg.GeminiKey[1] = cfg.GeminiKey[1], cfg.GeminiKey[0]
	cfg.GeminiKey[1].Prefix = "moved"
	cfg.GeminiKey[1].BaseURL = "https://changed.example"
	cfg.GeminiKey[1].ProxyURL = "http://proxy.example"
	cfg.GeminiKey[1].Headers = map[string]string{"X-Test": "changed"}
	auths, err := NewConfigSynthesizer().Synthesize(&SynthesisContext{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if auths[1].Attributes["grouping_id"] != id {
		t.Fatal("routing changed identity")
	}
}

func TestGroupingSynthesisEnabledRejectsMissingIdentity(t *testing.T) {
	cfg := groupingSynthesisConfig()
	if _, err := NewConfigSynthesizer().Synthesize(&SynthesisContext{Config: cfg}); err == nil {
		t.Fatal("enabled configuration without IDs accepted")
	}
	if cfg.GeminiKey[0].GroupingID != "" {
		t.Fatal("synthesis allocated an ID")
	}
}

func TestGroupingFileSynthesisMetadataIdentity(t *testing.T) {
	ctx := &SynthesisContext{Config: &config.Config{Grouping: config.GroupingConfig{Enabled: true}}}
	raw := []byte(`{"type":"codex","grouping_id":"37b70dba-3269-47f6-b823-aa921989b665"}`)
	auths, err := SynthesizeAuthFile(ctx, "credential.json", raw)
	if err != nil || len(auths) != 1 {
		t.Fatalf("synthesis: %v", err)
	}
	if auths[0].Attributes["grouping_id"] != "37b70dba-3269-47f6-b823-aa921989b665" {
		t.Fatal("metadata identity was not propagated")
	}
	if _, err = SynthesizeAuthFile(ctx, "credential.json", []byte(`{"type":"codex"}`)); err == nil {
		t.Fatal("enabled file without identity accepted")
	}
}

type groupingMultiParser struct{}

func (groupingMultiParser) ParseAuth(context.Context, pluginapi.AuthParseRequest) (*coreauth.Auth, bool, error) {
	return nil, true, nil
}

func (groupingMultiParser) ParseAuths(context.Context, pluginapi.AuthParseRequest) ([]*coreauth.Auth, bool, error) {
	return []*coreauth.Auth{{ID: "child-1"}, {ID: "child-2"}}, true, nil
}

func TestGroupingPluginSynthesisRejectsMissingChildIdentities(t *testing.T) {
	ctx := &SynthesisContext{Config: &config.Config{Grouping: config.GroupingConfig{Enabled: true}}, PluginAuthParser: groupingMultiParser{}}
	raw := []byte(`{"type":"plugin","grouping_id":"37b70dba-3269-47f6-b823-aa921989b665"}`)
	if _, err := SynthesizeAuthFile(ctx, "plugin.json", raw); err == nil {
		t.Fatal("plugin without persistent child IDs accepted")
	}
	ctx.Config.Grouping.Enabled = false
	auths, err := SynthesizeAuthFile(ctx, "plugin.json", raw)
	if err != nil || len(auths) != 2 {
		t.Fatalf("legacy synthesis: %v", err)
	}
	for _, auth := range auths {
		if auth.Attributes["grouping_id"] != "" {
			t.Fatal("file UUID inherited by child")
		}
	}
}
