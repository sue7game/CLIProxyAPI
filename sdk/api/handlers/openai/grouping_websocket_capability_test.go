package openai

import (
	"context"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestGroupingWebsocketCapabilitiesIgnoreUnauthorizedRoutes(t *testing.T) {
	const model = "grouping-scoped-ws-capability"
	manager, policy := newGroupingSessionManager(t, "codex", model)
	manager.RegisterExecutor(groupingCapabilityExecutor{provider: "codex"})
	allowed, _ := manager.GetByID(policy.authID)
	allowed.Attributes["websockets"] = "true"
	if _, errUpdate := manager.Update(context.Background(), allowed); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	const deniedID = "grouping-scoped-ws-denied"
	if _, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: deniedID, Provider: "openai"}); errRegister != nil {
		t.Fatal(errRegister)
	}
	r := registry.GetGlobalRegistry()
	r.RegisterClient(deniedID, "openai", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { r.UnregisterClient(deniedID) })
	h := NewOpenAIResponsesAPIHandler(&handlers.BaseAPIHandler{AuthManager: manager})
	ctx := access.WithAuthenticatedPrincipal(context.Background(), "test", "session-token")
	if !h.responsesWebsocketUsesUpstreamWebsocketPassthrough(model, ctx) || !h.websocketUpstreamSupportsCompactionReplayForModel(model, ctx) {
		t.Fatal("unauthorized route changed the permitted websocket transport")
	}
	if h.responsesWebsocketUsesUpstreamWebsocketPassthrough(model) {
		t.Fatal("missing trusted principal used global websocket capabilities")
	}
	policy.revoked.Store(true)
	if h.responsesWebsocketUsesUpstreamWebsocketPassthrough(model, ctx) {
		t.Fatal("revoked principal advertised websocket passthrough")
	}
	policy.revoked.Store(false)
	disabled := true
	if _, errOverride := manager.SetRuntimeAuthOverride(allowed.Index, coreauth.RuntimeAuthOverride{Disabled: &disabled}); errOverride != nil {
		t.Fatal(errOverride)
	}
	if h.responsesWebsocketUsesUpstreamWebsocketPassthrough(model, ctx) {
		t.Fatal("runtime-disabled credential advertised websocket passthrough")
	}
}

type groupingInterruptExecutor struct {
	coreauth.ProviderExecutor
	authID    string
	forwarded int
}

func (*groupingInterruptExecutor) Identifier() string { return "codex" }

func (e *groupingInterruptExecutor) InterruptExecutionSession(ctx context.Context, _ string, _ []byte) error {
	if !coreexecutor.WebsocketAuthEnabled(ctx, e.authID) {
		return errors.New("credential rejected")
	}
	e.forwarded++
	return nil
}

func TestGroupingWebsocketInterruptRechecksPermission(t *testing.T) {
	manager, policy := newGroupingSessionManager(t, "codex", "grouping-interrupt-policy")
	executor := &groupingInterruptExecutor{authID: policy.authID}
	manager.RegisterExecutor(executor)
	h := NewOpenAIResponsesAPIHandler(&handlers.BaseAPIHandler{AuthManager: manager})
	ctx := access.WithAuthenticatedPrincipal(context.Background(), "test", "session-token")
	payload := []byte(`{"type":"response.interrupt","response_id":"response"}`)
	if errInterrupt := h.forwardResponsesWebsocketInterrupt(ctx, "session", payload); errInterrupt != nil {
		t.Fatal(errInterrupt)
	}
	policy.revoked.Store(true)
	if errInterrupt := h.forwardResponsesWebsocketInterrupt(ctx, "session", payload); errInterrupt == nil {
		t.Fatal("revoked principal forwarded an interrupt")
	}
	if executor.forwarded != 1 {
		t.Fatalf("forwarded interrupts=%d, want 1", executor.forwarded)
	}
}
