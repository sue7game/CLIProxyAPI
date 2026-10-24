package cliproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type legacyUploadStore struct{ saved []*coreauth.Auth }

func (*legacyUploadStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (*legacyUploadStore) Delete(context.Context, string) error           { return nil }
func (s *legacyUploadStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	s.saved = append(s.saved, auth.Clone())
	return auth.FileName, nil
}

func assertLegacyAuthMetadata(t *testing.T, before, after []byte) {
	t.Helper()
	var want, got map[string]any
	if err := json.Unmarshal(before, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &got); err != nil {
		t.Fatal(err)
	}
	// Legacy Store.Save normalizes disabled and JSON formatting, but must not add grouping IDs.
	want["disabled"] = false
	if !reflect.DeepEqual(got, want) {
		t.Fatal("legacy upload changed credential metadata or injected a grouping identity")
	}
}

func TestGroupingLegacyUploadPersistsCustomStoreWithoutWatcher(t *testing.T) {
	f := newGroupingAuthFixture(t, false)
	store := &legacyUploadStore{}
	f.g.owner.coreManager.SetStore(store)
	for i, token := range []string{"initial-token", "replacement-token"} {
		raw := []byte(`{"type":"codex","access_token":"` + token + `"}`)
		if err := f.g.applyAuthFile(f.ctx, f.path("custom.json"), raw); err != nil {
			t.Fatal(err)
		}
		if len(store.saved) != i+1 || store.saved[i].Metadata["access_token"] != token {
			t.Fatalf("upload %d did not synchronously save exactly once", i)
		}
	}
}

func TestGroupingInitializedUploadDoesNotWriteCustomStore(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	store := &legacyUploadStore{}
	f.g.owner.coreManager.SetStore(store)
	f.apply(t, "managed.json")
	if len(store.saved) != 0 {
		t.Fatal("managed source transaction performed an extra store write")
	}
}

func TestGroupingLegacyUploadLocksPreviousCodexSource(t *testing.T) {
	for _, source := range []string{"disk", "manager"} {
		t.Run(source, func(t *testing.T) {
			f := newGroupingAuthFixture(t, false)
			path := f.path("replace.json")
			before := []byte(`{"type":"codex","access_token":"previous-token"}`)
			if source == "manager" {
				if _, err := f.g.owner.coreManager.Register(coreauth.WithSkipPersist(f.ctx), oauthTestRecord("replace.json")); err != nil {
					t.Fatal(err)
				}
				before = []byte(`{"type":"unknown"}`)
			}
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			assertLegacyCodexLock(t, f, path, before)
		})
	}
}

func assertLegacyCodexLock(t *testing.T, f *groupingAuthFixture, path string, before []byte) {
	t.Helper()
	locked, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unlock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unlock)
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- codex.WithFileLock(path, func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	uploadDone := make(chan error, 1)
	go func() {
		uploadDone <- f.g.applyAuthFile(f.ctx, path, []byte(`{"type":"claude","access_token":"replacement"}`))
	}()
	for range 200 {
		runtime.Gosched()
	}
	select {
	case err := <-uploadDone:
		t.Fatalf("upload bypassed existing Codex lock: %v", err)
	default:
	}
	if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, before) {
		t.Fatalf("upload modified locked source: %v", err)
	}
	unlock()
	if err := <-lockDone; err != nil {
		t.Fatal(err)
	}
	if err := <-uploadDone; err != nil {
		t.Fatal(err)
	}
}
