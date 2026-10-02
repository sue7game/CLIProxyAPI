package cliproxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	executor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"gopkg.in/yaml.v3"
)

const groupingInventoryModel = "grouping-inventory-model"

func newGroupingInventoryFixture(t *testing.T, disabled bool) *groupingIntegrationFixture {
	t.Helper()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auths")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	compat := config.OpenAICompatibility{
		Name: "inventory", BaseURL: "https://example.invalid/v1", Disabled: disabled,
		Models:        []config.OpenAICompatibilityModel{{Name: groupingInventoryModel}},
		APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "inventory-test-upstream"}},
	}
	cfg, err := config.ParseConfigBytes([]byte("api-keys: [integration-downstream-only]\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthDir, cfg.OpenAICompatibility = authDir, []config.OpenAICompatibility{compat}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	previous := sdkauth.GetTokenStore()
	t.Cleanup(func() { sdkauth.RegisterTokenStore(previous) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &groupingIntegrationFixture{path: path, authDir: authDir, ctx: ctx}
	if err := f.start(t); err != nil {
		t.Fatal(err)
	}
	f.initialize(t)
	return f
}

func groupingInventoryCredential(t *testing.T, f *groupingIntegrationFixture) *coreauth.Auth {
	t.Helper()
	auths, err := f.service.grouping.collectSources(f.service.cfg, nil)
	if err != nil || len(auths) != 1 {
		t.Fatalf("expected one inventory source, got %d: %v", len(auths), err)
	}
	return auths[0]
}

func setGroupingInventoryDisabled(t *testing.T, f *groupingIntegrationFixture, disabled bool) {
	t.Helper()
	current := f.service.cfg.CloneForRuntime()
	proposed := current.CloneForRuntime()
	proposed.OpenAICompatibility[0].Disabled = disabled
	request := management.ConfigApplyRequest{Current: current, Proposed: proposed, Operation: "inventory-test"}
	if err := f.service.applyGroupingConfigMutation(f.ctx, request); err != nil {
		t.Fatalf("set disabled=%v: %v", disabled, err)
	}
}

func assertGroupingInventoryScheduling(t *testing.T, f *groupingIntegrationFixture, auth *coreauth.Auth, disabled bool) {
	t.Helper()
	selected, err := f.service.coreManager.SelectAuth(f.principal(), auth.Provider, groupingInventoryModel, executor.Options{})
	if disabled {
		if err == nil || selected != nil {
			t.Error("disabled inventory source remained schedulable")
		}
		return
	}
	if err != nil || selected == nil || selected.Attributes["grouping_id"] != auth.Attributes["grouping_id"] {
		t.Fatalf("enabled source was not schedulable: %v", err)
	}
}
