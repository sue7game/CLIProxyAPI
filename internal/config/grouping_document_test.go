package config

import (
	"bytes"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

const groupingDocumentV8 = `config-version: 8
grouping: {enabled: false, store-path: ./policy/groups.json}
requests: {payload: {default: null}}
plugins:
  configs:
    example:
      enabled: false
      arbitrary: {null-setting: null, empty-setting: {}, list: []}
api-keys:
  gemini:
    - name: duplicates
      base-url: https://gemini.example.test
      headers: {X-Shared: original}
      keys:
        - api-key: same-secret
          headers: {}
          request-retry: null
        - api-key: same-secret
  openai-compatibility:
    - name: keyless
      base-url: https://openai.example.test
      keys: []
    - name: keyed
      base-url: https://openai.example.test
      keys:
        - api-key: shared-secret
        - api-key: shared-secret
oauth:
  providers:
    codex:
      live-media-relay:
        ice-servers:
          - urls: [turn:relay.example.test:3478]
            username: private-name
            credential: private-value
`

func TestPrepareGroupingConfigDocumentPreservesV8Tree(t *testing.T) {
	for _, normalized := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "runtime"}[normalized], func(t *testing.T) {
			var cfg *Config
			if normalized {
				var err error
				cfg, err = ParseConfigBytesPreservingCredentials([]byte(groupingDocumentV8))
				if err != nil {
					t.Fatal(err)
				}
			} else {
				cfg = new(Config)
				if err := yaml.Unmarshal([]byte(groupingDocumentV8), cfg); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := EnsureGroupingCredentialIDs(cfg); err != nil {
				t.Fatal(err)
			}
			got, err := PrepareGroupingConfigDocument([]byte(groupingDocumentV8), cfg)
			if err != nil {
				t.Fatal(err)
			}
			assertGroupingDocumentOnlyIDsChanged(t, []byte(groupingDocumentV8), got)
			if err = ValidateV8Config(got); err != nil {
				t.Fatal(err)
			}
			reloaded, err := ParseConfigBytes(got)
			if err != nil || len(reloaded.GeminiKey) != 2 || reloaded.GeminiKey[0].GroupingID == reloaded.GeminiKey[1].GroupingID {
				t.Fatal("duplicate source records lost independent identities", err)
			}
			if err = ValidateGroupingCredentialIDs(reloaded); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGroupingDocumentLegacyMigrationRetainsPolicyAndEveryID(t *testing.T) {
	raw := []byte("grouping: {enabled: true, store-path: ./private-policy}\ngemini-api-key: [{api-key: duplicate}, {api-key: duplicate}]\nvertex-api-key: [{api-key: duplicate}, {api-key: duplicate}]\n")
	cfg, err := ParseConfigBytesPreservingCredentials(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = EnsureGroupingCredentialIDs(cfg); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareGroupingConfigDocument(raw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	assertGroupingDocumentOnlyIDsChanged(t, raw, prepared)
	migrated, _, err := NormalizeConfigLayout(prepared, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateV8Config(migrated); err != nil {
		t.Fatal(err)
	}
	reloaded, err := ParseConfigBytes(migrated)
	if err != nil || !reflect.DeepEqual(GroupingCredentialSources(cfg), GroupingCredentialSources(reloaded)) || reloaded.Grouping != cfg.Grouping {
		t.Fatal("v8 migration lost grouping configuration or identities", err)
	}
}

func TestGroupingDocumentRejectsReorderedOrChangedSources(t *testing.T) {
	raw := []byte("config-version: 8\napi-keys:\n  codex:\n    - name: pair\n      base-url: https://codex.example.test\n      keys: [{api-key: first}, {api-key: second}]\n")
	for _, mutate := range []func(*Config){
		func(c *Config) { c.CodexKey = c.CodexKey[:1] },
		func(c *Config) { c.CodexKey[0], c.CodexKey[1] = c.CodexKey[1], c.CodexKey[0] },
		func(c *Config) { c.CodexKey[0].APIKey = "different" },
		func(c *Config) { c.CodexKey[1].GroupingID = c.CodexKey[0].GroupingID },
	} {
		cfg, err := ParseConfigBytesPreservingCredentials(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = EnsureGroupingCredentialIDs(cfg); err != nil {
			t.Fatal(err)
		}
		mutate(cfg)
		if _, err = PrepareGroupingConfigDocument(raw, cfg); err == nil {
			t.Fatal("ambiguous source correspondence was accepted")
		}
	}
}

func TestGroupingDocumentRawInvalidRecordsAreNotReassigned(t *testing.T) {
	raw := []byte("gemini-api-key: [{api-key: ''}, {api-key: valid}]\n")
	var source Config
	if err := yaml.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureGroupingCredentialIDs(&source); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareGroupingConfigDocument(raw, &source)
	if err != nil {
		t.Fatal(err)
	}
	assertGroupingDocumentOnlyIDsChanged(t, raw, prepared)
	loaded, err := ParseConfigBytes(prepared)
	if err != nil || len(loaded.GeminiKey) != 1 || loaded.GeminiKey[0].GroupingID != source.GeminiKey[1].GroupingID {
		t.Fatal("invalid source changed a valid source identity", err)
	}
	updated, err := PrepareGroupingConfigDocument(prepared, loaded)
	if err != nil {
		t.Fatal("ignored source prevented an unrelated update", err)
	}
	var restored Config
	if err = yaml.Unmarshal(updated, &restored); err != nil || len(restored.GeminiKey) != 2 || restored.GeminiKey[0].GroupingID != source.GeminiKey[0].GroupingID || restored.GeminiKey[1].GroupingID != source.GeminiKey[1].GroupingID {
		t.Fatal("ignored source IDs or live source mapping were changed", err)
	}
}

func assertGroupingDocumentOnlyIDsChanged(t *testing.T, before, after []byte) {
	t.Helper()
	normalize := func(data []byte) any {
		var value any
		if err := yaml.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		stripGroupingDocumentIDs(value)
		return value
	}
	if !reflect.DeepEqual(normalize(before), normalize(after)) {
		t.Fatal("identity preparation changed unrelated YAML semantics")
	}
	if !bytes.Contains(after, []byte("grouping-id:")) {
		t.Fatal("identity preparation did not write permanent IDs")
	}
}

func stripGroupingDocumentIDs(value any) {
	switch node := value.(type) {
	case map[string]any:
		delete(node, "grouping-id")
		for _, child := range node {
			stripGroupingDocumentIDs(child)
		}
	case []any:
		for _, child := range node {
			stripGroupingDocumentIDs(child)
		}
	}
}
