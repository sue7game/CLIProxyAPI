package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const fileGroupingTestID = "37b70dba-3269-47f6-b823-aa921989b665"
const fileGroupingOtherID = "6e05de62-63ad-4483-b880-b2068034233b"

func TestFileGroupingIDPreservedAcrossOAuthRefresh(t *testing.T) {
	for _, provider := range []string{"metadata", "codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			store := NewFileTokenStore()
			store.SetBaseDir(t.TempDir())
			auth := &coreauth.Auth{ID: "credential.json", Metadata: map[string]any{
				"type": "codex", "access_token": "old", "grouping_id": fileGroupingTestID,
			}}
			path, err := store.Save(context.Background(), auth)
			if err != nil {
				t.Fatal(err)
			}
			refreshed := &coreauth.Auth{ID: auth.ID, Metadata: map[string]any{"type": "codex", "access_token": "new"}}
			switch provider {
			case "codex":
				refreshed.Storage = &codex.CodexTokenStorage{AccessToken: "new"}
			case "claude":
				refreshed.Storage = &claude.ClaudeTokenStorage{AccessToken: "new"}
			}
			if _, err = store.Save(context.Background(), refreshed); err != nil {
				t.Fatal(err)
			}
			readFileGroupingID(t, path, fileGroupingTestID)
			loaded, err := store.List(context.Background())
			if err != nil || len(loaded) != 1 {
				t.Fatalf("list: %v", err)
			}
			if loaded[0].Attributes["grouping_id"] != fileGroupingTestID {
				t.Fatal("list dropped identity")
			}
		})
	}
}

func readFileGroupingID(t *testing.T, path, want string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	id, _ := saved["grouping_id"].(string)
	if id != want {
		t.Fatalf("saved identity = %q, want %q", id, want)
	}
}

func TestFileGroupingIDNoImplicitAllocation(t *testing.T) {
	store := NewFileTokenStore()
	store.SetBaseDir(t.TempDir())
	auth := &coreauth.Auth{ID: "legacy.json", Metadata: map[string]any{"type": "codex"}}
	path, err := store.Save(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	readFileGroupingID(t, path, "")
	loaded, err := store.List(context.Background())
	if err != nil || len(loaded) != 1 {
		t.Fatalf("list: %v", err)
	}
	if _, ok := loaded[0].Attributes["grouping_id"]; ok {
		t.Fatal("legacy record received identity")
	}
}

func TestFileGroupingIDConflictDoesNotOverwrite(t *testing.T) {
	store := NewFileTokenStore()
	dir := t.TempDir()
	store.SetBaseDir(dir)
	raw := []byte(`{"type":"codex","grouping_id":"` + fileGroupingTestID + `"}`)
	path := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	auth := &coreauth.Auth{ID: "credential.json", Metadata: map[string]any{"grouping_id": fileGroupingOtherID}}
	if _, err := store.Save(context.Background(), auth); err == nil {
		t.Fatal("identity replacement accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(raw) {
		t.Fatal("rejected save modified source file")
	}
}

func TestFileGroupingIDFromAttributesPersists(t *testing.T) {
	store := NewFileTokenStore()
	store.SetBaseDir(t.TempDir())
	auth := &coreauth.Auth{ID: "attribute.json", Attributes: map[string]string{"grouping_id": fileGroupingTestID}}
	path, err := store.Save(context.Background(), auth)
	if err != nil {
		t.Fatal(err)
	}
	readFileGroupingID(t, path, fileGroupingTestID)
}

func TestPluginGroupingRequiresIndependentPersistedIdentities(t *testing.T) {
	parent := map[string]any{"grouping_id": fileGroupingTestID}
	auths := []*coreauth.Auth{{ID: "one"}, {ID: "two"}}
	if err := ApplyFileGroupingIDs(auths, parent, true); err == nil {
		t.Fatal("missing child identities accepted")
	}
	if err := ApplyFileGroupingIDs(auths, parent, false); err != nil {
		t.Fatal(err)
	}
	for _, auth := range auths {
		if auth.Attributes["grouping_id"] != "" {
			t.Fatal("parent ID inherited by child")
		}
	}
	auths[0].Metadata = map[string]any{"grouping_id": fileGroupingTestID}
	auths[1].Metadata = map[string]any{"grouping_id": fileGroupingOtherID}
	if err := ApplyFileGroupingIDs(auths, parent, true); err == nil {
		t.Fatal("parent ID reused by child")
	}
	auths[0].Metadata["grouping_id"] = "478e6498-e218-45ac-9b4c-30c7062284bd"
	if err := ApplyFileGroupingIDs(auths, parent, true); err != nil {
		t.Fatal(err)
	}
	auths[1].Attributes["grouping_id"] = auths[0].Attributes["grouping_id"]
	auths[1].Metadata["grouping_id"] = auths[0].Metadata["grouping_id"]
	if err := ApplyFileGroupingIDs(auths, parent, true); err == nil {
		t.Fatal("duplicate child IDs accepted")
	}
}

type groupingUnsupportedStorage struct{ called bool }

func (s *groupingUnsupportedStorage) SaveTokenToFile(string) error {
	s.called = true
	return nil
}

func TestFileGroupingIDRejectsStorageWithoutMetadataSupport(t *testing.T) {
	store := NewFileTokenStore()
	store.SetBaseDir(t.TempDir())
	storage := &groupingUnsupportedStorage{}
	auth := &coreauth.Auth{ID: "unsupported.json", Storage: storage, Metadata: map[string]any{"grouping_id": fileGroupingTestID}}
	if _, err := store.Save(context.Background(), auth); err == nil {
		t.Fatal("storage unable to preserve UUID accepted")
	}
	if storage.called {
		t.Fatal("unsupported storage was invoked")
	}
}

func TestPluginGroupingRejectsRuntimeIDCollision(t *testing.T) {
	auths := []*coreauth.Auth{
		{ID: "same", Metadata: map[string]any{"grouping_id": fileGroupingTestID}},
		{ID: "same", Metadata: map[string]any{"grouping_id": fileGroupingOtherID}},
	}
	if err := ApplyFileGroupingIDs(auths, nil, true); err == nil {
		t.Fatal("plugin runtime ID collision accepted")
	}
}
