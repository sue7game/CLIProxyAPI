package cliproxy

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

const groupingV8DocumentFixture = `config-version: 8
server: {port: 8317}
access: {api-keys: [integration-downstream-only]}
api-keys:
  codex:
    - name: fixture-channel
      base-url: https://example.invalid/v1
      keys:
        - api-key: fixture-duplicate
        - api-key: fixture-duplicate
plugins:
  configs:
    sample:
      options: {} # Keep empty mapping
      custom-null: null # Keep explicit null
grouping: {enabled: false, store-path: grouping-policy}
`

func TestGroupingV8InitializationAndActivationPreserveDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte(groupingV8DocumentFixture)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	current, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	prepared, change, err := prepareGroupingConfig(path, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.CodexKey) != 2 || prepared.CodexKey[0].GroupingID == "" || prepared.CodexKey[0].GroupingID == prepared.CodexKey[1].GroupingID {
		t.Fatal("v8 initialization lost duplicate record identity")
	}
	assertGroupingV8DocumentPresence(t, change.after)
	prepared.Grouping.Enabled = true
	activation, err := prepareGroupingActivationConfig(path, change.after, prepared)
	if err != nil {
		t.Fatal(err)
	}
	assertGroupingV8DocumentPresence(t, activation.after)
	var persisted config.Config
	if err := yaml.Unmarshal(activation.after, &persisted); err != nil {
		t.Fatal(err)
	}
	if !persisted.Grouping.Enabled || !reflect.DeepEqual(persisted.CodexKey, prepared.CodexKey) {
		t.Fatal("activation changed source identities or failed to enable grouping")
	}
}

func assertGroupingV8DocumentPresence(t *testing.T, data []byte) {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["config-version"] != 8 || doc["port"] != nil || doc["codex-api-key"] != nil {
		t.Fatal("document reverted to a legacy layout")
	}
	plugins := doc["plugins"].(map[string]any)["configs"].(map[string]any)["sample"].(map[string]any)
	if options, ok := plugins["options"].(map[string]any); !ok || len(options) != 0 {
		t.Fatal("explicit plugin empty mapping was changed")
	}
	if value, ok := plugins["custom-null"]; !ok || value != nil {
		t.Fatal("explicit plugin null was changed")
	}
	for _, comment := range []string{"# Keep empty mapping", "# Keep explicit null"} {
		if !bytes.Contains(data, []byte(comment)) {
			t.Fatal("plugin comment was lost")
		}
	}
}

func TestGroupingV8ManagedDocumentRejectsStaleSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte(groupingV8DocumentFixture)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	request := management.ConfigApplyRequest{Current: cfg, Proposed: cfg, SourceYAML: raw, CanonicalYAML: raw}
	external := append(bytes.Clone(raw), []byte("# external edit\n")...)
	if err := os.WriteFile(path, external, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareManagedGroupingConfig(path, request, cfg, false); err == nil {
		t.Fatal("stale v8 source snapshot was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, external) {
		t.Fatal("rejected mutation overwrote an external change")
	}
}
