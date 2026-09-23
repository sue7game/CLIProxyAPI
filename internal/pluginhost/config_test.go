package pluginhost

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"gopkg.in/yaml.v3"
)

func TestRuntimeConfigYAMLAddsHostDefaultsToRawPluginConfig(t *testing.T) {
	var node yaml.Node
	if errDecode := yaml.Unmarshal([]byte("config1: true\nconfig2: value\n"), &node); errDecode != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", errDecode)
	}
	if len(node.Content) != 1 {
		t.Fatalf("yaml node content length = %d, want 1", len(node.Content))
	}
	item := config.PluginInstanceConfig{
		Priority: 3,
		Raw:      *node.Content[0],
	}

	got := string(runtimeConfigYAML(item, true))
	for _, want := range []string{
		"config1: true",
		"config2: value",
		"enabled: true",
		"priority: 3",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("runtimeConfigYAML() missing %q in:\n%s", want, got)
		}
	}
}

func TestRuntimeConfigYAMLDefaultsEnabledFalse(t *testing.T) {
	item := config.PluginInstanceConfig{
		Priority: 3,
	}

	got := string(runtimeConfigYAML(item, false))
	for _, want := range []string{
		"enabled: false",
		"priority: 3",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("runtimeConfigYAML() missing %q in:\n%s", want, got)
		}
	}
}

func TestRuntimeConfigYAMLOverridesHostControlledFields(t *testing.T) {
	var node yaml.Node
	if errDecode := yaml.Unmarshal([]byte("enabled: true\npriority: 99\nmode: safe\n"), &node); errDecode != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", errDecode)
	}
	item := config.PluginInstanceConfig{
		Priority: 3,
		Raw:      *node.Content[0],
	}

	got := string(runtimeConfigYAML(item, false))
	for _, want := range []string{"enabled: false", "priority: 3", "mode: safe"} {
		if !strings.Contains(got, want) {
			t.Fatalf("runtimeConfigYAML() missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "enabled: true") || strings.Contains(got, "priority: 99") {
		t.Fatalf("runtimeConfigYAML() retained stale host fields:\n%s", got)
	}
}

func TestRuntimeConfigFromConfigKeepsItemsDisabledWhenPluginsAreGloballyDisabled(t *testing.T) {
	enabled := true
	cfg := &config.Config{
		Plugins: config.PluginsConfig{
			Enabled: false,
			Dir:     "~/.cli-proxy-api/plugins",
			Configs: map[string]config.PluginInstanceConfig{
				"alpha": {Enabled: &enabled, Priority: 7},
			},
		},
	}

	got, errRuntimeConfig := runtimeConfigFromConfig(cfg)
	if errRuntimeConfig != nil {
		t.Fatalf("runtimeConfigFromConfig() error = %v", errRuntimeConfig)
	}
	item, ok := got.Items["alpha"]
	if !ok {
		t.Fatal("runtimeConfigFromConfig() omitted alpha while globally disabled")
	}
	if got.Enabled || item.Enabled {
		t.Fatalf("enabled state = global %t item %t, want false/false", got.Enabled, item.Enabled)
	}
	for _, raw := range [][]byte{item.ConfigYAML, item.DisabledConfigYAML} {
		if !strings.Contains(string(raw), "enabled: false") {
			t.Fatalf("disabled plugin config missing enabled: false:\n%s", string(raw))
		}
	}
}

func TestRuntimeConfigFromConfigExtractsStoreVersion(t *testing.T) {
	var node yaml.Node
	if errDecode := yaml.Unmarshal([]byte("store:\n  version: 1.0.3\n  release-tag: v1.0.3\n"), &node); errDecode != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", errDecode)
	}
	enabled := true
	cfg := &config.Config{
		Plugins: config.PluginsConfig{
			Enabled: true,
			Configs: map[string]config.PluginInstanceConfig{
				"alpha": {
					Enabled: &enabled,
					Raw:     *node.Content[0],
				},
			},
		},
	}

	got, errRuntimeConfig := runtimeConfigFromConfig(cfg)
	if errRuntimeConfig != nil {
		t.Fatalf("runtimeConfigFromConfig() error = %v", errRuntimeConfig)
	}
	if got.Items["alpha"].Version != "1.0.3" {
		t.Fatalf("runtimeConfigFromConfig() version = %q, want 1.0.3", got.Items["alpha"].Version)
	}
}

func TestRuntimeConfigFromConfigDerivesStoreVersionFromReleaseTag(t *testing.T) {
	var node yaml.Node
	if errDecode := yaml.Unmarshal([]byte("store:\n  release-tag: v1.0.3\n"), &node); errDecode != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", errDecode)
	}
	enabled := true
	cfg := &config.Config{
		Plugins: config.PluginsConfig{
			Enabled: true,
			Configs: map[string]config.PluginInstanceConfig{
				"alpha": {
					Enabled: &enabled,
					Raw:     *node.Content[0],
				},
			},
		},
	}

	got, errRuntimeConfig := runtimeConfigFromConfig(cfg)
	if errRuntimeConfig != nil {
		t.Fatalf("runtimeConfigFromConfig() error = %v", errRuntimeConfig)
	}
	if got.Items["alpha"].Version != "1.0.3" {
		t.Fatalf("runtimeConfigFromConfig() version = %q, want 1.0.3", got.Items["alpha"].Version)
	}
}
