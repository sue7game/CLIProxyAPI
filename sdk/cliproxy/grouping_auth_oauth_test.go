package cliproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestGroupingAuthOAuthStagesBeforeAtomicSaveAndPublication(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	record := oauthTestRecord("oauth.json")
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	id := record.Attributes["grouping_id"]
	if id == "" || f.snapshot(t).Identities[id].State != grouping.PendingRebind {
		t.Fatal("OAuth identity was not staged pending")
	}
	if _, err := os.Stat(f.path("oauth.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("prepare prematurely persisted source")
	}
	if err := f.g.owner.coreManager.AuthorizeCredentialUse(f.principal, record); err == nil {
		t.Fatal("pending credential authorized")
	}
	if _, err := f.files.Save(coreauth.WithAuthCreationIntent(f.ctx), record); err != nil {
		t.Fatal(err)
	}
	if f.snapshot(t).Identities[id].State != grouping.PendingRebind {
		t.Fatal("save activated before final verification")
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if identity := f.snapshot(t).Identities[id]; identity.State != grouping.Active || identity.GroupID != grouping.AllGroups {
		t.Fatal("finalize lost new grouping")
	}
	auth := f.record(t, "oauth.json")
	if err := f.g.owner.coreManager.AuthorizeCredentialUse(f.principal, auth); err != nil {
		t.Fatal(err)
	}
	if len(GlobalModelRegistry().GetModelsForClient(auth.ID)) == 0 {
		t.Fatal("OAuth success did not register models")
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, auth); err != nil {
		t.Fatalf("finalize is not idempotent: %v", err)
	}
}

func TestGroupingAuthOAuthReloginPreservesUUIDGroupAndMetadata(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	auth := f.apply(t, "relogin.json")
	groupID := f.restrict(t, auth)
	metadata, err := groupingAuthMetadata(f.read(t, "relogin.json"))
	if err != nil {
		t.Fatal(err)
	}
	metadata["note"] = "keep management note"
	if err := os.WriteFile(f.path("relogin.json"), encodeGroupingTestMetadata(t, metadata), 0600); err != nil {
		t.Fatal(err)
	}
	record := oauthTestRecord("relogin.json")
	delete(record.Metadata, "access_token")
	record.Storage = &codex.CodexTokenStorage{AccountID: "same-test-account", AccessToken: "relogged-temporary-token", RefreshToken: "temporary-refresh"}
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if record.Attributes["grouping_id"] != auth.Attributes["grouping_id"] {
		t.Fatal("relogin replaced source UUID")
	}
	if _, err := f.files.Save(coreauth.WithAuthCreationIntent(f.ctx), record); err != nil {
		t.Fatal(err)
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	identity := f.snapshot(t).Identities[record.Attributes["grouping_id"]]
	if identity.GroupID != groupID || identity.State != grouping.Active {
		t.Fatal("relogin lost group")
	}
	persisted, err := groupingAuthMetadata(f.read(t, "relogin.json"))
	if err != nil || persisted["note"] != "keep management note" || persisted["access_token"] != "relogged-temporary-token" {
		t.Fatal("relogin lost metadata or new token")
	}
}

func TestGroupingAuthOAuthRefreshAndStatusPostHookAreIdempotent(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	auth := f.apply(t, "refresh.json")
	groupID := f.restrict(t, auth)
	before := f.snapshot(t)
	auth.Metadata["access_token"] = "refreshed-temporary-token"
	auth.Disabled, auth.Metadata["disabled"] = true, true
	if _, err := f.files.Save(f.ctx, auth); err != nil {
		t.Fatal(err)
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, auth); err != nil {
		t.Fatal(err)
	}
	if !f.record(t, "refresh.json").Disabled {
		t.Fatal("post hook did not synchronize disabled state")
	}
	after := f.snapshot(t)
	if after.Revision != before.Revision || after.Identities[auth.Attributes["grouping_id"]].GroupID != groupID {
		t.Fatal("unchanged identity rotated policy or group")
	}
}

func TestGroupingAuthOAuthConcurrentPreparationsConflictWithoutLosingPending(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	a := oauthTestRecord("first.json")
	if err := f.g.prepareOAuthRecord(f.ctx, a); err != nil {
		t.Fatal(err)
	}
	b := oauthTestRecord("second.json")
	if err := f.g.prepareOAuthRecord(f.ctx, b); !errors.Is(err, grouping.ErrConflict) {
		t.Fatalf("overlapping prepare accepted: %v", err)
	}
	if b.Attributes["grouping_id"] != "" {
		t.Fatal("rejected prepare mutated record")
	}
	if f.snapshot(t).Identities[a.Attributes["grouping_id"]].State != grouping.PendingRebind {
		t.Fatal("rejected prepare changed first transaction")
	}
	if _, err := f.files.Save(coreauth.WithAuthCreationIntent(f.ctx), a); err != nil {
		t.Fatal(err)
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, a); err != nil {
		t.Fatal(err)
	}
}

func TestGroupingAuthOAuthJournalNeverContainsTokens(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	record := oauthTestRecord("secrets.json")
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(f.g.path, "config.pending"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("temporary-oauth-token")) || bytes.Contains(raw, []byte("same-test-account")) {
		t.Fatal("journal contains credential material")
	}
	var intent groupingSourceIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		t.Fatal(err)
	}
	if intent.BeforeExists || !intent.AfterExists || intent.BeforeHash != "" || intent.SourcePath != f.path("secrets.json") {
		t.Fatal("journal omitted canonical existence-bound source")
	}
}
