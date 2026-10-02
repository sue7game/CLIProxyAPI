package cliproxy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestGroupingAuthOAuthUnknownPersistedBytesFailClosed(t *testing.T) {
	for _, phase := range []string{"before-save", "after-save"} {
		t.Run(phase, func(t *testing.T) {
			f := newGroupingAuthFixture(t, true)
			record := oauthTestRecord("oauth.json")
			if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
				t.Fatal(err)
			}
			if phase == "after-save" {
				if _, err := f.files.Save(coreauth.WithAuthCreationIntent(f.ctx), record); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(f.path("oauth.json"), []byte(`{"type":"codex","account_id":"unapproved"}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := f.g.finalizeOAuthRecord(f.ctx, record); !errors.Is(err, grouping.ErrUnavailable) {
				t.Fatalf("unknown file finalized: %v", err)
			}
			if _, err := f.g.store.Snapshot(); !errors.Is(err, grouping.ErrUnavailable) {
				t.Fatal("failed finalize left authorization live")
			}
			if _, ok := f.g.owner.coreManager.GetByID("oauth.json"); ok {
				t.Fatal("failed finalize published runtime source")
			}
		})
	}
}

func TestGroupingAuthOAuthRejectsSaveToUnexpectedPath(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	record := oauthTestRecord("expected.json")
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := record.Storage.SaveTokenToFile(f.path("unexpected.json")); err == nil {
		t.Fatal("prepared storage wrote an unsigned path")
	}
	if _, err := os.Stat(f.path("unexpected.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected file created")
	}
	if !f.g.unavailable.Load() {
		t.Fatal("uncertain save did not fail closed")
	}
}

func TestGroupingAuthOAuthRejectsMutationAfterPrepare(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	record := oauthTestRecord("mutated.json")
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	record.Metadata["account_id"] = "different-account"
	if _, err := f.files.Save(coreauth.WithAuthCreationIntent(f.ctx), record); err == nil {
		t.Fatal("post-prepare metadata mutation accepted")
	}
	if _, err := os.Stat(f.path("mutated.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unapproved metadata written")
	}
}

func TestGroupingAuthOAuthWithoutPrepareCannotRegisterUnknownSource(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	record := oauthTestRecord("unregistered.json")
	record.Metadata["grouping_id"] = uuid.NewString()
	if _, err := f.files.Save(coreauth.WithAuthCreationIntent(f.ctx), record); err != nil {
		t.Fatal(err)
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, record); err == nil {
		t.Fatal("post-only hook granted all to unknown source")
	}
	if !f.g.sourcesUnavailable.Load() {
		t.Fatal("source mismatch did not close health gate")
	}
	if len(f.snapshot(t).Identities) != 1 {
		t.Fatal("post-only hook registered an identity")
	}
}

func TestGroupingAuthOAuthPendingSourceRecoveredOnlyFromKnownBytes(t *testing.T) {
	for _, written := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-save", true: "after-save"}[written], func(t *testing.T) {
			f := newGroupingAuthFixture(t, true)
			record := oauthTestRecord("recovery.json")
			if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
				t.Fatal(err)
			}
			id := record.Attributes["grouping_id"]
			if written {
				if _, err := f.files.Save(coreauth.WithAuthCreationIntent(f.ctx), record); err != nil {
					t.Fatal(err)
				}
			}
			reopenConfigJournalStore(t, f.g)
			if err := f.g.recoverSourceTransaction(); err != nil {
				t.Fatal(err)
			}
			identity, exists := f.snapshot(t).Identities[id]
			if written && (!exists || identity.State != grouping.Active) || !written && exists {
				t.Fatal("recovery guessed wrong source state")
			}
			if _, err := os.Stat(filepath.Join(f.g.path, "config.pending")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("recovered journal retained")
			}
		})
	}
}

func TestGroupingAuthSourceHealthCanRecoverWithoutResettingGroups(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	auth := f.apply(t, "known.json")
	groupID := f.restrict(t, auth)
	raw := f.read(t, "known.json")
	if err := os.WriteFile(f.path("known.json"), []byte(`{"type":"codex","account_id":"wrong"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, auth); err == nil {
		t.Fatal("identity loss accepted")
	}
	if err := os.WriteFile(f.path("known.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, auth); err != nil {
		t.Fatal(err)
	}
	if f.g.sourcesUnavailable.Load() || f.snapshot(t).Identities[auth.Attributes["grouping_id"]].GroupID != groupID {
		t.Fatal("recovered source lost restrictions")
	}
}
