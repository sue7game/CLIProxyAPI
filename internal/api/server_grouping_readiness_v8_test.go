package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

type groupingReadinessTestPolicy struct{ unhealthy bool }

func (p groupingReadinessTestPolicy) BeginAttempt(context.Context) (coreauth.CredentialAccessScope, error) {
	if p.unhealthy {
		return nil, &coreauth.Error{Code: "grouping_unavailable", HTTPStatus: http.StatusServiceUnavailable}
	}
	return groupingReadinessTestScope{}, nil
}

type groupingReadinessTestScope struct{}

func (groupingReadinessTestScope) Allows(*coreauth.Auth) bool { return true }
func (groupingReadinessTestScope) AuthorizeUse(context.Context, *coreauth.Auth) error {
	return nil
}

func TestGroupingReadinessKeepsBothManagementVersionsRecoverable(t *testing.T) {
	for _, state := range []string{"missing", "unhealthy", "healthy"} {
		t.Run(state, func(t *testing.T) {
			s := groupingReadinessTestServer(t, state)
			for _, version := range []string{"v0", "v8"} {
				path := "/" + version + "/management/config"
				for _, authorized := range []bool{true, false} {
					want := http.StatusUnauthorized
					key := ""
					if authorized {
						want, key = http.StatusOK, "local-management-test"
					}
					if response := groupingReadinessRequest(s, "GET", path, "", key); response.Code != want {
						t.Fatalf("%s (%s): status=%d want=%d", path, state, response.Code, want)
					}
				}
			}
			want := http.StatusServiceUnavailable
			if state == "healthy" {
				want = http.StatusOK
			}
			if response := groupingReadinessRequest(s, "GET", "/v1/models", "", "inference-test"); response.Code != want {
				t.Fatalf("model API (%s): status=%d want=%d body=%s", state, response.Code, want, response.Body.String())
			}
			if state != "healthy" {
				body := `{"model":"grouping-control-test-model","messages":[{"role":"user","content":"test"}]}`
				if response := groupingReadinessRequest(s, "POST", "/v1/chat/completions", body, "inference-test"); response.Code != http.StatusServiceUnavailable {
					t.Fatalf("inference (%s): status=%d want=503", state, response.Code)
				}
			}
		})
	}
}

func groupingReadinessTestServer(t *testing.T, state string) *Server {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "local-management-test")
	cfg := &config.Config{Grouping: config.GroupingConfig{Enabled: true}, SDKConfig: config.SDKConfig{APIKeys: []string{"inference-test"}}}
	s := newTestServerWithConfig(t, cfg, WithLocalManagementPassword("local-management-test"))
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(s.configFilePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if state != "missing" {
		s.handlers.AuthManager.SetCredentialAccessPolicy(groupingReadinessTestPolicy{unhealthy: state == "unhealthy"})
	}
	id := "grouping-control-test-" + state
	if _, err = s.handlers.AuthManager.Register(context.Background(), &coreauth.Auth{
		ID: id, Provider: "codex", Attributes: map[string]string{"grouping_id": "446015d6-c2da-43d5-af7c-330c0dad55c3"},
	}); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "grouping-control-test-model", Object: "model", OwnedBy: "codex"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	return s
}

func groupingReadinessRequest(s *Server, method, path, body, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	response := httptest.NewRecorder()
	s.engine.ServeHTTP(response, req)
	return response
}

func TestGroupingReadinessManagementExemptionIsExact(t *testing.T) {
	for _, path := range []string{"/management.html", "/v0/management/config", "/v8/management/grouping/status"} {
		if !isGroupingManagementPath(path) {
			t.Fatal("recovery control path was not exempted", path)
		}
	}
	for _, path := range []string{"/v8/management-extra", "/v0/management-extra/config", "/v1/chat/completions", "/management.html/proxy"} {
		if isGroupingManagementPath(path) {
			t.Fatal("nonmanagement path bypassed grouping readiness", path)
		}
	}
}
