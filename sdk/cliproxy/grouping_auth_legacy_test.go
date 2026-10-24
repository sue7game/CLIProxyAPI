package cliproxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGroupingAuthLegacyWithoutConfigFileAndWithLinkedAuthDir(t *testing.T) {
	f := newGroupingAuthFixture(t, false)
	cfg := f.g.current.Load().CloneForRuntime()
	linked := filepath.Join(t.TempDir(), "auth-link")
	if err := os.Symlink(cfg.AuthDir, linked); err != nil {
		t.Fatal(err)
	}
	cfg.AuthDir = linked
	f.g.current.Store(cfg)
	f.g.owner.cfg = cfg
	f.g.owner.configPath = ""
	raw := []byte(`{"type":"codex","access_token":"temporary-legacy-token"}`)
	if err := f.g.applyAuthFile(f.ctx, f.path("legacy.json"), raw); err != nil {
		t.Fatal(err)
	}
	assertLegacyAuthMetadata(t, raw, f.read(t, "legacy.json"))
	if f.record(t, "legacy.json").Attributes["grouping_id"] != "" {
		t.Fatal("legacy SDK upload injected a grouping identity")
	}
}

func TestGroupingAuthLegacyHooksDoNotMaskMissingEnabledStore(t *testing.T) {
	f := newGroupingAuthFixture(t, false)
	cfg := f.g.current.Load().CloneForRuntime()
	cfg.Grouping.Enabled = true
	f.g.current.Store(cfg)
	if err := f.g.applyAuthFile(f.ctx, f.path("missing.json"), []byte(`{"type":"codex"}`)); err == nil {
		t.Fatal("enabled grouping used the legacy upload fallback")
	}
	record := oauthTestRecord("missing.json")
	if err := f.g.prepareOAuthRecord(f.ctx, record); err == nil {
		t.Fatal("enabled grouping used the legacy OAuth prepare fallback")
	}
	if err := f.g.finalizeOAuthRecord(f.ctx, record); err == nil {
		t.Fatal("enabled grouping used the legacy OAuth finalize fallback")
	}
}
