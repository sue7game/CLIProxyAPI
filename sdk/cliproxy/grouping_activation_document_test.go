package cliproxy

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

func TestGroupingActivationDocumentAcceptsNullAndIsolatesAliases(t *testing.T) {
	tests := map[string]string{
		"null":            "grouping: null # grouping comment\n",
		"tilde":           "grouping: ~\n",
		"implicit-null":   "grouping:\n",
		"missing":         "other: false\n",
		"alias-map":       "defaults: &settings {enabled: false, store-path: policy, custom: null}\ngrouping: *settings\nother: *settings\n",
		"alias-null":      "defaults: &settings null\ngrouping: *settings\nother: *settings\n",
		"outgoing-alias":  "grouping: &settings {enabled: false, store-path: policy, custom: null}\nother: *settings\n",
		"incoming-scalar": "default: &flag false\ngrouping: {enabled: *flag}\nother: *flag\n",
		"outgoing-scalar": "grouping: {enabled: &flag false}\nother: *flag\n",
		"merged-map":      "defaults: &settings {enabled: false, store-path: policy}\ngrouping: {<<: *settings}\nother: *settings\n",
		"unrelated-alias": "defaults: &opaque {empty: {}, null: null}\nother: *opaque\ngrouping: {enabled: false}\n",
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			verifyGroupingActivationDocument(t, document)
		})
	}
}

func verifyGroupingActivationDocument(t *testing.T, document string) {
	t.Helper()
	raw := []byte(document + "opaque: {empty: {}, explicit-null: null} # opaque comment\n")
	expected := decodeGroupingActivationDocument(t, raw)
	settings := make(map[string]any)
	if original, ok := expected["grouping"].(map[string]any); ok {
		for key, value := range original {
			settings[key] = value
		}
	}
	settings["enabled"] = true
	expected["grouping"] = settings
	cfg := &config.Config{Grouping: config.GroupingConfig{Enabled: true}}
	change, err := prepareGroupingActivationConfig("fixture.yaml", raw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, change.before) || change.path != "fixture.yaml" {
		t.Fatal("activation lost source CAS bytes or destination")
	}
	if actual := decodeGroupingActivationDocument(t, change.after); !reflect.DeepEqual(actual, expected) {
		t.Fatalf("activation changed values outside grouping.enabled: got %#v, want %#v", actual, expected)
	}
	if !bytes.Contains(change.after, []byte("# opaque comment")) {
		t.Fatal("activation lost an unrelated comment")
	}
}

func TestGroupingNullDocumentCanActivateAfterInitialization(t *testing.T) {
	for _, value := range []string{"null", "~"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			raw := []byte("grouping: " + value + "\ncodex-api-key:\n  - api-key: activation-fixture\n    base-url: https://example.invalid/v1\n")
			writeGroupingSourceGuardFile(t, path, raw)
			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			initialized, initial, err := prepareGroupingConfig(path, cfg)
			if err != nil {
				t.Fatal(err)
			}
			initialized.Grouping.Enabled = true
			activated, err := prepareGroupingActivationConfig(path, initial.after, initialized)
			if err != nil {
				t.Fatal(err)
			}
			var actual config.Config
			if err := yaml.Unmarshal(activated.after, &actual); err != nil {
				t.Fatal(err)
			}
			if !actual.Grouping.Enabled || !reflect.DeepEqual(actual.CodexKey, initialized.CodexKey) {
				t.Fatal("activation failed or altered initialized source identities")
			}
		})
	}
}

func TestGroupingActivationDocumentRejectsMalformedGrouping(t *testing.T) {
	for _, document := range []string{"grouping: false\n", "grouping: invalid\n", "grouping: []\n", "value: &invalid false\ngrouping: *invalid\n", "grouping: &cycle {self: *cycle}\n"} {
		cfg := &config.Config{Grouping: config.GroupingConfig{Enabled: true}}
		if _, err := prepareGroupingActivationConfig("fixture.yaml", []byte(document), cfg); !errors.Is(err, grouping.ErrInvalid) {
			t.Fatalf("malformed grouping was not rejected: %v", err)
		}
	}
}

func decodeGroupingActivationDocument(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	return root
}
