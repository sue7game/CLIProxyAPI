package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

type groupingIntegrationFixture struct {
	service *Service
	backend groupingapi.Backend
	path    string
	authDir string
	ctx     context.Context
}

func newGroupingIntegrationFixture(t *testing.T) *groupingIntegrationFixture {
	t.Helper()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auths")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	data := fmt.Sprintf("auth-dir: %q\napi-keys:\n  - integration-downstream-only\ncodex-api-key:\n  - api-key: integration-upstream-only\n    base-url: https://example.invalid/v1\n  - api-key: integration-upstream-only\n    base-url: https://example.invalid/v1\ngrouping:\n  enabled: false\n  store-path: grouping-policy\n", authDir)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"account-a.json", "account-b.json"} {
		data := []byte(`{"type":"codex","account_id":"integration-account","access_token":"integration-oauth-only"}`)
		if err := os.WriteFile(filepath.Join(authDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	previous := sdkauth.GetTokenStore()
	t.Cleanup(func() { sdkauth.RegisterTokenStore(previous) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &groupingIntegrationFixture{path: path, authDir: authDir, ctx: ctx}
	if err := f.start(t); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *groupingIntegrationFixture) start(t *testing.T) error {
	t.Helper()
	cfg, err := config.LoadConfig(f.path)
	if err != nil {
		return err
	}
	fileStore := sdkauth.NewFileTokenStore()
	fileStore.SetBaseDir(f.authDir)
	sdkauth.RegisterTokenStore(fileStore)
	service := &Service{cfg: cfg, configPath: f.path, coreManager: coreauth.NewManager(fileStore, nil, nil)}
	f.service = service
	err = service.prepareGrouping(f.ctx)
	t.Cleanup(func() {
		for _, auth := range service.coreManager.List() {
			GlobalModelRegistry().UnregisterClient(auth.ID)
		}
		if err := service.grouping.close(); err != nil {
			t.Error(err)
		}
	})
	if err != nil {
		return err
	}
	f.backend, err = service.grouping.backend()
	return err
}

func (f *groupingIntegrationFixture) initialize(t *testing.T) groupingapi.Status {
	t.Helper()
	status, err := f.backend.Initialize(f.ctx)
	if err != nil {
		t.Fatalf("real Service initialization failed: %v", err)
	}
	return status
}

func (f *groupingIntegrationFixture) snapshot(t *testing.T) grouping.Snapshot {
	t.Helper()
	snapshot, err := f.service.grouping.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func (f *groupingIntegrationFixture) restart(t *testing.T) error {
	t.Helper()
	if err := f.service.grouping.close(); err != nil {
		return err
	}
	return f.start(t)
}

func (f *groupingIntegrationFixture) principal() context.Context {
	return sdkaccess.WithAuthenticatedPrincipal(f.ctx, sdkaccess.DefaultAccessProviderName, "integration-downstream-only")
}

func TestGroupingIntegrationInitializePreservesDuplicateSources(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	status := f.initialize(t)
	if !status.Initialized || !status.Healthy || status.Enabled || f.service.grouping.enabled.Load() || f.service.cfg.Grouping.Enabled {
		t.Fatalf("initialization activated enforcement or failed: %+v", status)
	}
	snapshot := f.snapshot(t)
	if len(snapshot.Identities) != 5 || status.Revision != snapshot.Revision {
		t.Fatalf("duplicate sources lost: identities=%d response revision=%d store revision=%d", len(snapshot.Identities), status.Revision, snapshot.Revision)
	}
	for _, identity := range snapshot.Identities {
		if _, err := uuid.Parse(identity.ID); err != nil || identity.GroupID != "all" || identity.State != grouping.Active {
			t.Fatalf("invalid initialized identity: kind=%s state=%s", identity.Kind, identity.State)
		}
	}
	assertGroupingIntegrationSourceIDs(t, f)
	if _, err := f.backend.Initialize(f.ctx); err == nil {
		t.Fatal("second initialization replaced an existing policy")
	}
}

func assertGroupingIntegrationSourceIDs(t *testing.T, f *groupingIntegrationFixture) {
	t.Helper()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Grouping.Enabled || len(cfg.CodexKey) != 2 || cfg.CodexKey[0].GroupingID == cfg.CodexKey[1].GroupingID {
		t.Fatal("duplicate YAML records did not receive separate persistent identities")
	}
	ids := make(map[string]bool)
	for _, key := range cfg.CodexKey {
		ids[key.GroupingID] = true
	}
	for _, name := range []string{"account-a.json", "account-b.json"} {
		data, err := os.ReadFile(filepath.Join(f.authDir, name))
		if err != nil {
			t.Fatal(err)
		}
		var metadata map[string]any
		if err := json.Unmarshal(data, &metadata); err != nil {
			t.Fatal(err)
		}
		id, _ := metadata["grouping_id"].(string)
		if _, err := uuid.Parse(id); err != nil || ids[id] {
			t.Fatal("duplicate OAuth records did not receive distinct UUIDs")
		}
		ids[id] = true
	}
	if len(ids) != 4 || len(f.service.coreManager.List()) != 4 {
		t.Fatal("runtime publication lost independent credential records")
	}
}
