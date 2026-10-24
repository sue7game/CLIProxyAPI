package cliproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type groupingAuthFixture struct {
	g         *groupingService
	files     *sdkauth.FileTokenStore
	ctx       context.Context
	principal context.Context
}

func newGroupingAuthFixture(t *testing.T, initialized bool) *groupingAuthFixture {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authDir := filepath.Join(dir, "auths")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("api-keys: [temporary-test-downstream]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AuthDir: authDir}
	cfg.APIKeys = []string{"temporary-test-downstream"}
	cfg.Grouping.Enabled = initialized
	cfg.Grouping.StorePath = filepath.Join(dir, "policy")
	files := sdkauth.NewFileTokenStore()
	files.SetBaseDir(authDir)
	s := &Service{cfg: cfg, configPath: configPath, coreManager: coreauth.NewManager(files, nil, nil)}
	g := &groupingService{owner: s, path: filepath.Join(dir, "policy")}
	g.current.Store(cfg.CloneForRuntime())
	s.grouping = g
	if initialized {
		g.store, err = grouping.InitializeStore(g.path, grouping.NewSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := g.store.Fingerprint("token:"+sdkaccess.DefaultAccessProviderName, cfg.APIKeys[0])
		if err != nil {
			t.Fatal(err)
		}
		_, err = g.store.Update(1, func(snapshot *grouping.Snapshot) error {
			return snapshot.Register(grouping.Identity{Binding: grouping.Binding{ID: uuid.NewString(), Kind: grouping.Token, GroupID: grouping.AllGroups, State: grouping.Active}, Provider: sdkaccess.DefaultAccessProviderName, Fingerprint: fingerprint})
		})
		if err != nil {
			t.Fatal(err)
		}
		g.enabled.Store(true)
		g.installPolicy()
	}
	t.Cleanup(func() {
		for _, auth := range s.coreManager.List() {
			GlobalModelRegistry().UnregisterClient(auth.ID)
		}
		if g.store != nil {
			if err := g.store.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	ctx := context.Background()
	return &groupingAuthFixture{g: g, files: files, ctx: ctx, principal: sdkaccess.WithAuthenticatedPrincipal(ctx, sdkaccess.DefaultAccessProviderName, cfg.APIKeys[0])}
}

func (f *groupingAuthFixture) path(name string) string {
	return filepath.Join(f.g.current.Load().AuthDir, name)
}

func (f *groupingAuthFixture) snapshot(t *testing.T) grouping.Snapshot {
	t.Helper()
	snapshot, err := f.g.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func (f *groupingAuthFixture) record(t *testing.T, name string) *coreauth.Auth {
	t.Helper()
	auth, ok := f.g.owner.coreManager.GetByID(name)
	if !ok {
		t.Fatal("credential was not published")
	}
	return auth
}

func (f *groupingAuthFixture) read(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(f.path(name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *groupingAuthFixture) apply(t *testing.T, name string) *coreauth.Auth {
	t.Helper()
	if err := f.g.applyAuthFile(f.ctx, f.path(name), []byte(`{"type":"codex","account_id":"same-test-account","access_token":"temporary-upstream"}`)); err != nil {
		t.Fatal(err)
	}
	return f.record(t, name)
}

func (f *groupingAuthFixture) restrict(t *testing.T, auth *coreauth.Auth) string {
	t.Helper()
	snapshot := f.snapshot(t)
	var groupID string
	_, err := f.g.store.Update(snapshot.Revision, func(snapshot *grouping.Snapshot) error {
		group, err := snapshot.CreateGroup("Restricted")
		if err != nil {
			return err
		}
		groupID = group.ID
		return snapshot.Bind([]string{auth.Attributes["grouping_id"]}, group.ID)
	})
	if err != nil {
		t.Fatal(err)
	}
	return groupID
}

func oauthTestRecord(name string) *coreauth.Auth {
	return &coreauth.Auth{ID: name, FileName: name, Provider: "codex", Status: coreauth.StatusActive,
		Metadata: map[string]any{"type": "codex", "account_id": "same-test-account", "access_token": "temporary-oauth-token"}}
}

func encodeGroupingTestMetadata(t *testing.T, metadata map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
