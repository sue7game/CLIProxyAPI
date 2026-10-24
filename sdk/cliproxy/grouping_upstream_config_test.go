package cliproxy

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestGroupingWritesPublishCurrentSourceHash(t *testing.T) {
	f := newGroupingHTTPFixture(t)
	assertHash := func() {
		t.Helper()
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		want := internalconfig.ComputeSourceHash(raw)
		if got := f.service.currentConfig().SourceHash; got != want {
			t.Fatalf("service source hash = %q, want %q", got, want)
		}
		if got := f.service.grouping.current.Load().SourceHash; got != want {
			t.Fatalf("grouping source hash = %q, want %q", got, want)
		}
	}
	f.managed(t, http.MethodPatch, "/config/observability/logs/debug", true, 0)
	assertHash()
	f.managed(t, http.MethodPost, "/grouping/initialize", gin.H{}, 0)
	assertHash()
	f.managed(t, http.MethodPatch, "/grouping/activation", gin.H{"enabled": true}, f.snapshot(t).Revision)
	assertHash()
	f.managed(t, http.MethodPatch, "/config/observability/logs/debug", false, 0)
	assertHash()
	if f.service.currentConfig().Debug {
		t.Fatal("v8 mutation did not publish after grouping activation")
	}
}

func TestGroupingOAuthRenderRemovesCodexLockArtifacts(t *testing.T) {
	f := newGroupingAuthFixture(t, true)
	record := oauthTestRecord("render-lock.json")
	record.Storage = &codex.CodexTokenStorage{AccountID: "same-test-account", AccessToken: "render-test-token"}
	if err := f.g.prepareOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(f.g.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".oauth-render-") {
			t.Fatal("OAuth rendering left a temporary directory or lockfile")
		}
	}
}
