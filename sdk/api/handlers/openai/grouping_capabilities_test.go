package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type groupingCapabilityExecutor struct {
	coreauth.ProviderExecutor
	provider  string
	supported bool
}

func (e groupingCapabilityExecutor) Identifier() string       { return e.provider }
func (e groupingCapabilityExecutor) SupportsApplyPatch() bool { return e.supported }

func groupingCapabilityFixture(t *testing.T, supported bool) (*OpenAIAPIHandler, *sessionGroupingPolicy) {
	t.Helper()
	manager, policy := newGroupingSessionManager(t, "grouping-patch-allowed", "grouping-patch-alias")
	manager.RegisterExecutor(groupingCapabilityExecutor{provider: "grouping-patch-allowed", supported: supported})
	manager.RegisterExecutor(groupingCapabilityExecutor{provider: "grouping-patch-denied", supported: !supported})
	const deniedID = "grouping-patch-denied-auth"
	if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: deniedID, Provider: "grouping-patch-denied"}); err != nil {
		t.Fatal(err)
	}
	r := registry.GetGlobalRegistry()
	r.RegisterClient(policy.authID, "grouping-patch-allowed", []*registry.ModelInfo{
		{ID: "grouping-patch-alias", MetadataModelID: "gpt-5.5", Description: "scoped description", ExplicitInputModalities: true, SupportedInputModalities: []string{"text"}},
		{ID: "grouping-patch-synthetic", SupportedInputModalities: []string{"text"}},
		{ID: "gpt-image-2"},
	})
	r.RegisterClient(deniedID, "grouping-patch-denied", []*registry.ModelInfo{
		{ID: "grouping-patch-alias", MetadataModelID: "gpt-image-2", Description: "private metadata"},
		{ID: "grouping-patch-secret"},
	})
	t.Cleanup(func() { r.UnregisterClient(deniedID) })
	return NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)), policy
}

func requestGroupingCapabilities(h *OpenAIAPIHandler, trusted bool) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/models?client_version=cpa", nil)
	if trusted {
		trustedGroupingRequest(c)
	}
	h.OpenAIModels(c)
	return recorder
}

func TestGroupingCodexV8CapabilitiesUseOnlyAuthorizedProviders(t *testing.T) {
	for _, supported := range []bool{true, false} {
		t.Run(map[bool]string{true: "supported", false: "unsupported"}[supported], func(t *testing.T) {
			h, _ := groupingCapabilityFixture(t, supported)
			for _, enabled := range []bool{false, true, false} {
				h.UpdateClients(&sdkconfig.SDKConfig{Client: sdkconfig.ClientConfig{Codex: sdkconfig.CodexClientConfig{
					EnableApplyPatch: enabled, OptimizeMultiAgentV2: enabled,
				}}})
				response := requestGroupingCapabilities(h, true)
				if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("catalog = %d %s", response.Code, response.Body.String())
				}
				if strings.Contains(response.Body.String(), "private metadata") || strings.Contains(response.Body.String(), "grouping-patch-secret") {
					t.Fatal("unauthorized metadata entered the catalog")
				}
				assertGroupingCapabilities(t, response.Body.Bytes(), enabled, supported)
			}
		})
	}
}

func assertGroupingCapabilities(t *testing.T, body []byte, enabled, supported bool) {
	t.Helper()
	var payload struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Models) != 3 {
		t.Fatalf("models = %d, want 3", len(payload.Models))
	}
	for _, entry := range payload.Models {
		var want any
		if enabled && supported && entry["slug"] != "gpt-image-2" {
			want = "freeform"
		}
		if got, exists := entry["apply_patch_tool_type"]; !exists || got != want {
			t.Errorf("%s apply_patch = %v (present %v), want %v", entry["slug"], got, exists, want)
		}
		if enabled && entry["multi_agent_version"] != "v2" {
			t.Errorf("%s lost the v8 multi-agent flag", entry["slug"])
		}
	}
}

func TestGroupingCodexV8CapabilityCatalogFailsClosed(t *testing.T) {
	h, policy := groupingCapabilityFixture(t, true)
	h.UpdateClients(&sdkconfig.SDKConfig{Client: sdkconfig.ClientConfig{Codex: sdkconfig.CodexClientConfig{EnableApplyPatch: true}}})
	for _, trusted := range []bool{false, true} {
		policy.revoked.Store(trusted)
		response := requestGroupingCapabilities(h, trusted)
		if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "grouping-patch-alias") {
			t.Fatalf("denied catalog = %d %s", response.Code, response.Body.String())
		}
	}
	policy.revoked.Store(false)
	h.AuthManager.SetCredentialAccessPolicy(nil)
	response := requestGroupingCapabilities(h, false)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "grouping-patch-secret") {
		t.Fatalf("disabled catalog = %d %s", response.Code, response.Body.String())
	}
}
