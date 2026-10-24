package management

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestConfigV8GroupingRespondsAfterSynchronousPublication(t *testing.T) {
	f := newV8GroupingFixture(t, v8GroupingDocument)
	entered, release := make(chan struct{}), make(chan struct{})
	f.h.SetConfigApplyHook(func(ctx context.Context, req ConfigApplyRequest) error {
		close(entered)
		<-release
		return f.commit(t, req)
	})
	before, previous := f.read(t), f.h.cfg.CloneForRuntime()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.request("PATCH", "/v8/management/config", `{"routing":{"retry":{"request-retry":7}}}`, "")
	}()
	<-entered
	select {
	case <-done:
		t.Fatal("response completed before the synchronous controller")
	default:
	}
	unchanged := bytes.Equal(before, f.read(t)) && reflect.DeepEqual(previous, f.h.cfg)
	close(release)
	response := <-done
	if !unchanged || response.Code != http.StatusOK || f.h.cfg.RequestRetry != 7 {
		t.Fatal("transaction did not isolate then publish the candidate")
	}
}

func TestConfigV8GroupingPluginDeletionPreservesCanonicalTree(t *testing.T) {
	f := newV8GroupingFixture(t, v8GroupingDocument)
	f.router.DELETE("/v8/management/plugins/sample", func(c *gin.Context) {
		if f.h.commitPluginConfig(c, "plugin.delete", func(candidate *config.Config) error {
			delete(candidate.Plugins.Configs, "sample")
			return nil
		}) {
			c.Status(http.StatusOK)
		}
	})
	response := f.request("DELETE", "/v8/management/plugins/sample", "", "")
	if response.Code != http.StatusOK || len(f.calls) != 1 || len(f.h.cfg.Plugins.Configs) != 0 {
		t.Fatalf("plugin transaction failed: %d %s", response.Code, response.Body.String())
	}
	for _, fragment := range []string{"default: null", "retained-secret", v8GroupingIDFirst, v8GroupingIDSecond} {
		if !bytes.Contains(f.read(t), []byte(fragment)) {
			t.Fatal("plugin operation changed unrelated configuration")
		}
	}
}

func TestConfigV8GroupingCredentialStatusOverridesInheritance(t *testing.T) {
	raw := strings.Replace(v8GroupingDocument, `"keys":[`, `"excluded-models":["*"],"keys":[`, 1)
	f := newV8GroupingFixture(t, raw)
	id, _ := synthesizer.NewStableIDGenerator().Next("codex:apikey", "same-key", "https://codex.example.test", "", "", "")
	auth := &coreauth.Auth{ID: id, Provider: "codex", Attributes: map[string]string{
		"api_key": "same-key", "base_url": "https://codex.example.test", "source": "config:codex[0]", "grouping_id": v8GroupingIDFirst,
	}}
	f.router.PATCH("/v8/management/credentials/status", func(c *gin.Context) {
		f.h.applyConfigAuthStatusV8(c, auth, false)
	})
	response := f.request("PATCH", "/v8/management/credentials/status", `{}`, "")
	if response.Code != http.StatusOK || len(f.calls) != 1 {
		t.Fatalf("status transaction failed: %d %s", response.Code, response.Body.String())
	}
	if len(f.h.cfg.CodexKey[0].ExcludedModels) != 0 || !reflect.DeepEqual(f.h.cfg.CodexKey[1].ExcludedModels, []string{"*"}) {
		t.Fatal("status toggle changed sibling credentials or inherited the disabled group value")
	}
	assertV8GroupingRetainedFields(t, f)
}

func TestConfigV8GroupingJSONRoundTripPreservesTURNSecrets(t *testing.T) {
	f := newV8GroupingFixture(t, v8GroupingDocument)
	read := f.request("GET", "/v8/management/config", "", "")
	if read.Code != http.StatusOK || strings.Contains(read.Body.String(), "retained-secret") || strings.Contains(read.Body.String(), "retained-user") {
		t.Fatal("JSON view exposed TURN credentials")
	}
	response := f.request("PUT", "/v8/management/config", read.Body.String(), read.Header().Get("ETag"))
	if response.Code != http.StatusOK {
		t.Fatalf("JSON roundtrip failed: %d %s", response.Code, response.Body.String())
	}
	assertV8GroupingRetainedFields(t, f)
}

func TestConfigV8GroupingStatusRejectsReusedRuntimeOrdinal(t *testing.T) {
	f := newV8GroupingFixture(t, v8GroupingDocument)
	id, _ := synthesizer.NewStableIDGenerator().Next("codex:apikey", "same-key", "https://codex.example.test", "", "", "")
	stale := &coreauth.Auth{ID: id, Provider: "codex", Attributes: map[string]string{
		"api_key": "same-key", "base_url": "https://codex.example.test", "source": "config:codex[0]", "grouping_id": v8GroupingIDSecond,
	}}
	f.router.PATCH("/v8/management/credentials/status", func(c *gin.Context) {
		f.h.applyConfigAuthStatusV8(c, stale, true)
	})
	before := f.read(t)
	response := f.request("PATCH", "/v8/management/credentials/status", `{}`, "")
	if response.Code != 409 || len(f.calls) != 0 || !bytes.Equal(before, f.read(t)) {
		t.Fatal("stale runtime ordinal changed a different logical credential")
	}
}

func TestConfigV8GroupingStatusPreservesIgnoredMiddleSource(t *testing.T) {
	const ignoredID = "26d3a560-e53a-4898-acad-d58b2aaf360c"
	sources := `[{"name":"first","base-url":"https://codex.example.test","keys":[{"api-key":"same-key","grouping-id":"` + v8GroupingIDFirst + `"}]},{"name":"ignored","keys":[{"api-key":"","grouping-id":"` + ignoredID + `"}]},{"name":"second","base-url":"https://codex.example.test","keys":[{"api-key":"same-key","grouping-id":"` + v8GroupingIDSecond + `"}]}]`
	f := newV8GroupingFixture(t, strings.Replace(v8GroupingDocument, v8GroupingSources, sources, 1))
	id, _ := synthesizer.NewStableIDGenerator().Next("codex:apikey", "same-key", "https://codex.example.test", "", "", "")
	auth := &coreauth.Auth{ID: id, Provider: "codex", Attributes: map[string]string{
		"api_key": "same-key", "base_url": "https://codex.example.test", "source": "config:codex[0]", "grouping_id": v8GroupingIDFirst,
	}}
	f.router.PATCH("/v8/management/credentials/status", func(c *gin.Context) {
		f.h.applyConfigAuthStatusV8(c, auth, true)
	})
	response := f.request("PATCH", "/v8/management/credentials/status", `{}`, "")
	if response.Code != http.StatusOK || len(f.h.cfg.CodexKey) != 2 {
		t.Fatalf("status update was blocked by an ignored source: %d %s", response.Code, response.Body.String())
	}
	if !reflect.DeepEqual(f.h.cfg.CodexKey[0].ExcludedModels, []string{"*"}) || len(f.h.cfg.CodexKey[1].ExcludedModels) != 0 || !bytes.Contains(f.read(t), []byte(ignoredID)) {
		t.Fatal("status update changed the ignored or sibling source")
	}
}
