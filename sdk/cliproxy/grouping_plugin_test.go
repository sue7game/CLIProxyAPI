package cliproxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func TestGroupingPluginAuthFileBridgePublishesRegisteredSource(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	f.initialize(t)
	raw := []byte(`{"type":"codex","account_id":"plugin-fixture-account","access_token":"plugin-fixture-not-live"}`)
	path, err := f.service.grouping.applyPluginAuthFile(f.ctx, "plugin-fixture.json", raw)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(f.authDir, "plugin-fixture.json") {
		t.Fatal("plugin escaped configured auth directory")
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(persisted, &metadata); err != nil {
		t.Fatal(err)
	}
	id, ok := metadata["grouping_id"].(string)
	if !ok || id == "" {
		t.Fatal("plugin source omitted stable UUID")
	}
	identity := f.snapshot(t).Identities[id]
	if identity.Kind != grouping.Credential || identity.GroupID != grouping.AllGroups || identity.State != grouping.Active {
		t.Fatal("plugin source was not registered before returning success")
	}
	found := false
	for _, auth := range f.service.coreManager.List() {
		found = found || auth.Attributes["grouping_id"] == id
	}
	if !found {
		t.Fatal("plugin source was not synchronously published")
	}
}

func TestGroupingPluginAuthFileBridgeRejectsUnsafeNames(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	for _, name := range []string{"", "../escape.json", "sub/file.json", `sub\file.json`, "credential.yaml", "/tmp/escape.json"} {
		if _, err := f.service.grouping.applyPluginAuthFile(f.ctx, name, []byte(`{}`)); err == nil {
			t.Errorf("accepted unsafe plugin name %q", name)
		}
	}
}
