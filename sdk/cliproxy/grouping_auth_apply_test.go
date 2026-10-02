package cliproxy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func TestGroupingAuthLegacyDoesNotInjectIDs(t *testing.T) {
	f := newGroupingAuthFixture(t, false)
	raw := []byte(" {\"type\":\"codex\",\"access_token\":\"temporary\"}\n")
	if err := f.g.applyAuthFile(f.ctx, f.path("legacy.json"), raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.read(t, "legacy.json"), raw) {
		t.Fatal("legacy bytes changed")
	}
	if f.record(t, "legacy.json").Attributes["grouping_id"] != "" {
		t.Fatal("legacy upload allocated a UUID")
	}
	record := oauthTestRecord("legacy-oauth.json")
	before := record.Clone()
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if record.Attributes["grouping_id"] != "" || record.Storage != before.Storage {
		t.Fatal("legacy hooks changed OAuth persistence")
	}
}

func TestGroupingAuthUploadPublishesSchedulableIndependentRecords(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	a := f.apply(t, "first.json")
	b := f.apply(t, "second.json")
	idA, idB := a.Attributes["grouping_id"], b.Attributes["grouping_id"]
	if idA == idB || uuid.Validate(idA) != nil || uuid.Validate(idB) != nil {
		t.Fatal("duplicate accounts merged source IDs")
	}
	snapshot := f.snapshot(t)
	for _, id := range []string{idA, idB} {
		if identity := snapshot.Identities[id]; identity.State != grouping.Active || identity.GroupID != grouping.AllGroups {
			t.Fatal("new source not activated in all")
		}
	}
	if err := f.g.owner.coreManager.AuthorizeCredentialUse(f.principal, a); err != nil {
		t.Fatal(err)
	}
	if len(GlobalModelRegistry().GetModelsForClient(a.ID)) == 0 {
		t.Fatal("successful upload omitted model registration")
	}
	if info, err := os.Stat(f.path("first.json")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("source permissions are not private")
	}
	if _, err := os.Stat(filepath.Join(f.g.path, "config.pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful upload left a pending journal")
	}
}

func TestGroupingAuthReplacementPreservesGroupAndRejectsUUIDTransplant(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	auth := f.apply(t, "account.json")
	groupID := f.restrict(t, auth)
	id := auth.Attributes["grouping_id"]
	old := f.snapshot(t).Identities[id]
	raw := []byte(`{"type":"codex","account_id":"replacement-account","access_token":"new-temporary-token"}`)
	if err := f.g.applyAuthFile(f.ctx, f.path("account.json"), raw); err != nil {
		t.Fatal(err)
	}
	next := f.snapshot(t).Identities[id]
	if next.GroupID != groupID || next.ID != old.ID || next.Fingerprint == old.Fingerprint || next.State != grouping.Active {
		t.Fatal("replacement lost grouping or fingerprint")
	}
	committed := f.read(t, "account.json")
	for _, test := range []struct{ name, id string }{{"account.json", uuid.NewString()}, {"copied.json", id}} {
		bad := encodeGroupingTestMetadata(t, map[string]any{"type": "codex", "account_id": "replacement-account", "grouping_id": test.id})
		if err := f.g.applyAuthFile(f.ctx, f.path(test.name), bad); !errors.Is(err, grouping.ErrConflict) {
			t.Fatalf("UUID transplant accepted: %v", err)
		}
	}
	if !bytes.Equal(f.read(t, "account.json"), committed) {
		t.Fatal("rejected replacement altered source")
	}
	if after := f.snapshot(t).Identities[id]; after != next {
		t.Fatal("rejected replacement changed policy")
	}
}

func TestGroupingAuthRejectsInvalidSourcesWithoutDefaultAll(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"type":"codex"}`, `{"type":"codex","grouping_id":null}`, `{"account_id":"without-provider"}`} {
		t.Run(raw, func(t *testing.T) {
			f := newGroupingAuthFixture(t, true)
			before := f.snapshot(t)
			if err := f.g.applyAuthFile(f.ctx, f.path("invalid.json"), []byte(raw)); err == nil {
				t.Fatal("invalid source accepted")
			}
			if _, err := os.Stat(f.path("invalid.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid source persisted")
			}
			if got := f.snapshot(t); got.Revision != before.Revision {
				t.Fatal("invalid source acquired a default identity")
			}
		})
	}
}

func TestGroupingAuthOfflineIdentityConflictFailsClosed(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	f.apply(t, "registered.json")
	raw := f.read(t, "registered.json")
	if err := os.WriteFile(f.path("duplicate.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.g.applyAuthFile(f.ctx, f.path("third.json"), []byte(`{"type":"codex","account_id":"third"}`)); err == nil {
		t.Fatal("duplicate disk UUID accepted")
	}
	if !f.g.sourcesUnavailable.Load() {
		t.Fatal("ambiguous sources did not fail closed")
	}
	if err := f.g.owner.coreManager.AuthorizeCredentialUse(f.principal, f.record(t, "registered.json")); err == nil {
		t.Fatal("unhealthy source store still authorizes")
	}
}

func TestGroupingAuthPathBoundaryRejectsLinksAndNestedSources(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	external := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(external, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, f.path("link.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.path("nested"), 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"type":"codex","account_id":"new"}`)
	for _, path := range []string{external, f.path("link.json"), f.path("nested/child.json"), f.path("wrong.yaml")} {
		if err := f.g.applyAuthFile(f.ctx, path, raw); err == nil {
			t.Fatal("unsafe source path accepted")
		}
	}
	if data, err := os.ReadFile(external); err != nil || string(data) != "original" {
		t.Fatal("external file changed")
	}
}

func TestGroupingAuthConcurrentUploadsRemainConsistent(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, name := range []string{"a.json", "b.json"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			errs <- f.g.applyAuthFile(f.ctx, f.path(name), []byte(`{"type":"codex","account_id":"same"}`))
		}(name)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(f.snapshot(t).Identities) != 3 || len(f.g.owner.coreManager.List()) != 2 {
		t.Fatal("concurrent source publication lost records")
	}
	cancelled, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := f.g.applyAuthFile(cancelled, f.path("cancelled.json"), []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled write was started")
	}
}

func TestGroupingAuthUploadPreservesUnrelatedPendingSource(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	auth := f.apply(t, "pending.json")
	groupID := f.restrict(t, auth)
	snapshot := f.snapshot(t)
	id := auth.Attributes["grouping_id"]
	if _, err := f.g.store.Update(snapshot.Revision, func(snapshot *grouping.Snapshot) error {
		return snapshot.SetIdentityState(id, grouping.PendingRebind)
	}); err != nil {
		t.Fatal(err)
	}
	f.apply(t, "new.json")
	if identity := f.snapshot(t).Identities[id]; identity.State != grouping.PendingRebind || identity.GroupID != groupID {
		t.Fatal("unrelated pending source was reactivated or moved to all")
	}
	if err := f.g.owner.coreManager.AuthorizeCredentialUse(f.principal, auth); err == nil {
		t.Fatal("unrelated pending source became usable")
	}
}
