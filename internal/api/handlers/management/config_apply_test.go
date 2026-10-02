package management

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func newConfigApplyTestHandler(t *testing.T) (*Handler, *config.Config, []byte) {
	t.Helper()
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"old-token"}}, Grouping: config.GroupingConfig{Enabled: true}}
	raw := []byte("grouping:\n  enabled: true\napi-keys:\n  - old-token\n")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return &Handler{cfg: cfg, configFilePath: path}, cfg, raw
}

func configApplyRequest(h *Handler, method, target, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	switch method {
	case http.MethodPatch:
		h.PatchAPIKeys(c)
	case http.MethodPut:
		h.PutAPIKeys(c)
	case http.MethodDelete:
		h.DeleteAPIKeys(c)
	}
	return recorder
}

func assertConfigApplyUnchanged(t *testing.T, h *Handler, source *config.Config, raw []byte) {
	t.Helper()
	if len(source.APIKeys) != 1 || source.APIKeys[0] != "old-token" || h.cfg != source {
		t.Fatal("rejected request polluted shared configuration")
	}
	actual, err := os.ReadFile(h.configFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(raw) {
		t.Fatal("rejected request changed disk configuration")
	}
}

func TestConfigApplyRejectsWithoutPollutingSharedConfig(t *testing.T) {
	h, source, raw := newConfigApplyTestHandler(t)
	h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
		if req.Current == source || req.Proposed == source {
			t.Fatal("hook received shared configuration")
		}
		req.Current.APIKeys[0] = "changed-snapshot"
		req.Proposed.APIKeys[0] = "changed-candidate"
		return errors.New("secret-from-controller")
	})
	response := configApplyRequest(h, "PATCH", "/api-keys", `{"old":"old-token","new":"new-token"}`)
	if response.Code != 500 {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "secret-from-controller") {
		t.Fatal("internal error leaked to response")
	}
	assertConfigApplyUnchanged(t, h, source, raw)
}

func TestConfigApplyRotationCarriesExplicitIdentityIntent(t *testing.T) {
	h, source, _ := newConfigApplyTestHandler(t)
	h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
		if req.Operation != "api-keys.patch" || req.TokenRotation == nil || req.TokenRotation.Old != "old-token" || req.TokenRotation.New != "new-token" {
			t.Fatal("missing explicit rotation intent")
		}
		if source.APIKeys[0] != "old-token" || req.Current.APIKeys[0] != "old-token" || req.Proposed.APIKeys[0] != "new-token" {
			t.Fatal("incorrect isolated snapshots")
		}
		h.SetConfig(req.Proposed.CloneForRuntime())
		return nil
	})
	response := configApplyRequest(h, "PATCH", "/api-keys", `{"old":"old-token","new":"new-token"}`)
	if response.Code != 200 || h.cfg.APIKeys[0] != "new-token" {
		t.Fatalf("apply failed: %d", response.Code)
	}
	if source.APIKeys[0] != "old-token" {
		t.Fatal("original shared config mutated")
	}
}

func TestConfigApplyBulkTokenReplacementIsAmbiguous(t *testing.T) {
	h, source, raw := newConfigApplyTestHandler(t)
	h.SetConfigApplyHook(func(context.Context, ConfigApplyRequest) error {
		t.Fatal("ambiguous replacement reached hook")
		return nil
	})
	response := configApplyRequest(h, "PUT", "/api-keys", `["new-token"]`)
	if response.Code != 409 {
		t.Fatalf("status = %d", response.Code)
	}
	assertConfigApplyUnchanged(t, h, source, raw)
}

func TestConfigApplyAllowsUnambiguousTokenAddAndDelete(t *testing.T) {
	h, source, _ := newConfigApplyTestHandler(t)
	var calls int
	h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
		calls++
		if req.TokenRotation != nil {
			t.Fatal("add/delete incorrectly inferred rotation")
		}
		return nil
	})
	if response := configApplyRequest(h, "PUT", "/api-keys", `["old-token","new-token"]`); response.Code != 200 {
		t.Fatalf("add status = %d", response.Code)
	}
	if response := configApplyRequest(h, "DELETE", "/api-keys?index=1", ""); response.Code != 200 {
		t.Fatalf("delete status = %d", response.Code)
	}
	if calls != 2 || len(h.cfg.APIKeys) != 1 || h.cfg.APIKeys[0] != "old-token" || len(source.APIKeys) != 1 {
		t.Fatal("unexpected committed configuration")
	}
}

func TestConfigApplyRequiresHookInGroupingMode(t *testing.T) {
	h, source, raw := newConfigApplyTestHandler(t)
	response := configApplyRequest(h, "PATCH", "/api-keys", `{"old":"old-token","new":"new-token"}`)
	if response.Code != 503 {
		t.Fatalf("status = %d", response.Code)
	}
	assertConfigApplyUnchanged(t, h, source, raw)
}

func TestConfigApplyRejectsModeBeforeHook(t *testing.T) {
	for _, invalid := range []string{"home"} {
		t.Run(invalid, func(t *testing.T) {
			h, source, raw := newConfigApplyTestHandler(t)
			if invalid == "identity" {
				source.GeminiKey = []config.GeminiKey{{APIKey: "credential"}}
			} else {
				source.Home.Enabled = true
			}
			h.SetConfigApplyHook(func(context.Context, ConfigApplyRequest) error {
				t.Fatal("invalid configuration reached hook")
				return nil
			})
			response := configApplyRequest(h, "PATCH", "/api-keys", `{"old":"old-token","new":"new-token"}`)
			if response.Code != 409 {
				t.Fatalf("status = %d", response.Code)
			}
			assertConfigApplyUnchanged(t, h, source, raw)
		})
	}
}

func TestConfigApplyDelegatesMissingCredentialIdentityToController(t *testing.T) {
	h, _, _ := newConfigApplyTestHandler(t)
	h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
		if len(req.Proposed.GeminiKey) != 1 || req.Proposed.GeminiKey[0].GroupingID != "" {
			t.Fatal("candidate did not preserve uninitialized source identity")
		}
		_, err := config.EnsureGroupingCredentialIDs(req.Proposed)
		return err
	})
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest("PUT", "/gemini-api-key", nil)
	ok := h.applyConfigMutation(c, "PutGeminiKeys", func(candidate *config.Config) (*APIKeyRotation, error) {
		candidate.GeminiKey = []config.GeminiKey{{APIKey: "new-source"}}
		return nil, nil
	})
	if !ok || h.cfg.GeminiKey[0].GroupingID == "" {
		t.Fatal("controller-generated source identity was not published")
	}
}

func TestConfigApplyResponseWaitsForSynchronousCommit(t *testing.T) {
	h, _, _ := newConfigApplyTestHandler(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h.SetConfigApplyHook(func(context.Context, ConfigApplyRequest) error {
		close(entered)
		<-release
		return nil
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- configApplyRequest(h, "PATCH", "/api-keys", `{"old":"old-token","new":"new-token"}`) }()
	<-entered
	select {
	case <-done:
		t.Fatal("request returned before transaction commit")
	default:
	}
	close(release)
	if response := <-done; response.Code != 200 {
		t.Fatalf("status = %d", response.Code)
	}
}
