package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGroupingCredentialIDsInitializeAndRoundTrip(t *testing.T) {
	cfg := groupingTestConfig()
	if err := ValidateGroupingCredentialIDs(cfg); err == nil {
		t.Fatal("missing identities accepted")
	}
	changed, err := EnsureGroupingCredentialIDs(cfg)
	if err != nil || !changed {
		t.Fatalf("initialize: changed=%v error=%v", changed, err)
	}
	if cfg.Grouping.Enabled {
		t.Fatal("initialization enabled grouping")
	}
	if changed, err = EnsureGroupingCredentialIDs(cfg); err != nil || changed {
		t.Fatalf("second initialization: changed=%v error=%v", changed, err)
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored Config
	if err = yaml.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if err = ValidateGroupingCredentialIDs(&restored); err != nil {
		t.Fatal(err)
	}
	if restored.CodexKey[0].GroupingID != cfg.CodexKey[0].GroupingID {
		t.Fatal("round trip changed identity")
	}
}

func groupingTestConfig() *Config {
	return &Config{
		GeminiKey:          []GeminiKey{{APIKey: "same"}, {APIKey: "same"}},
		InteractionsKey:    []GeminiKey{{APIKey: "same"}},
		ClaudeKey:          []ClaudeKey{{APIKey: "same"}},
		CodexKey:           []CodexKey{{APIKey: "same"}},
		XAIKey:             []XAIKey{{APIKey: "same"}},
		MetaKey:            []MetaKey{{APIKey: "same"}},
		VertexCompatAPIKey: []VertexCompatKey{{APIKey: "same"}, {APIKey: "same"}},
		OpenAICompatibility: []OpenAICompatibility{
			{Name: "no-key"},
			{Name: "keys", APIKeyEntries: []OpenAICompatibilityAPIKey{{APIKey: "same"}, {APIKey: "same"}}},
		},
	}
}

func TestGroupingCredentialIDsPreserveDuplicateSecrets(t *testing.T) {
	cfg := groupingTestConfig()
	if _, err := EnsureGroupingCredentialIDs(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.SanitizeGeminiKeys()
	cfg.SanitizeInteractionsKeys()
	cfg.SanitizeVertexCompatKeys()
	if len(cfg.GeminiKey) != 2 || len(cfg.VertexCompatAPIKey) != 2 {
		t.Fatal("independent credential records were deduplicated")
	}
	if cfg.GeminiKey[0].GroupingID == cfg.GeminiKey[1].GroupingID {
		t.Fatal("duplicate secrets share an identity")
	}
	if err := ValidateGroupingCredentialIDs(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestGroupingCredentialIDsRejectInvalidWithoutPartialMutation(t *testing.T) {
	for _, id := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000", " "} {
		cfg := &Config{CodexKey: []CodexKey{{}, {GroupingID: id}}}
		if changed, err := EnsureGroupingCredentialIDs(cfg); err == nil || changed {
			t.Fatalf("invalid ID %q accepted or mutated", id)
		}
		if cfg.CodexKey[0].GroupingID != "" {
			t.Fatal("failed validation partially initialized IDs")
		}
	}
	cfg := groupingTestConfig()
	if _, err := EnsureGroupingCredentialIDs(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ClaudeKey[0].GroupingID = strings.ToUpper(cfg.CodexKey[0].GroupingID)
	if err := ValidateGroupingCredentialIDs(cfg); err == nil {
		t.Fatal("case-insensitive duplicate UUID accepted")
	}
	if changed, err := EnsureGroupingCredentialIDs(cfg); err == nil || changed {
		t.Fatal("duplicate UUID accepted by initializer")
	}
}

func TestGroupingCredentialIDsRetainRoutingIndependentIdentity(t *testing.T) {
	cfg := groupingTestConfig()
	if _, err := EnsureGroupingCredentialIDs(cfg); err != nil {
		t.Fatal(err)
	}
	id := cfg.GeminiKey[0].GroupingID
	cfg.GeminiKey[0], cfg.GeminiKey[1] = cfg.GeminiKey[1], cfg.GeminiKey[0]
	cfg.GeminiKey[1].BaseURL = "https://changed.example"
	cfg.GeminiKey[1].Prefix = "changed"
	cfg.GeminiKey[1].Headers = map[string]string{"X-Test": "changed"}
	cfg.GeminiKey[1].ProxyURL = "http://proxy.example"
	if changed, err := EnsureGroupingCredentialIDs(cfg); err != nil || changed {
		t.Fatalf("routing change allocated new identity: %v %v", changed, err)
	}
	if cfg.GeminiKey[1].GroupingID != id {
		t.Fatal("reordering changed identity")
	}
}

func TestValidateGroupingMode(t *testing.T) {
	for _, home := range []bool{false, true} {
		for _, grouping := range []bool{false, true} {
			cfg := &Config{Home: HomeConfig{Enabled: home}, Grouping: GroupingConfig{Enabled: grouping}}
			err := ValidateGroupingMode(cfg)
			if (err != nil) != (home && grouping) {
				t.Fatalf("home=%v grouping=%v error=%v", home, grouping, err)
			}
			if cfg.Home.Enabled != home || cfg.Grouping.Enabled != grouping {
				t.Fatal("mode validation mutated configuration")
			}
		}
	}
	if err := ValidateGroupingMode(nil); err == nil {
		t.Fatal("nil configuration accepted")
	}
}
