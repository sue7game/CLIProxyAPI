package pluginhost

import (
	"context"
	"encoding/json"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestHostAuthSetRuntimeOverrideCallbackUpdatesOnlyRuntimeRouting(t *testing.T) {
	auth := &coreauth.Auth{
		ID:       "antigravity-runtime",
		Provider: "antigravity",
		Status:   coreauth.StatusActive,
		ProxyURL: "http://configured-proxy.example.com:8080",
		Attributes: map[string]string{
			"priority":     "14",
			"runtime_only": "true",
		},
	}
	host := New()
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	registered, errRegister := host.currentAuthManager().Register(context.Background(), auth)
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	disabled := true
	priority := 13
	proxyURL := "direct"
	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex: registered.Index,
		Disabled:  &disabled,
		Priority:  &priority,
		ProxyURL:  &proxyURL,
	})
	if errMarshal != nil {
		t.Fatalf("Marshal() error = %v", errMarshal)
	}

	rawResponse, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthSetRuntimeOverride, rawRequest)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthSetRuntimeOverrideResponse](rawResponse)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if !response.Auth.EffectiveDisabled || response.Auth.ConfiguredDisabled {
		t.Fatalf("auth disabled state = %#v, want runtime-only disabled", response.Auth)
	}
	if response.Auth.ConfiguredPriority != 14 || response.Auth.EffectivePriority != 13 {
		t.Fatalf("auth priority state = %#v, want 14 configured and 13 effective", response.Auth)
	}
	if response.Auth.ConfiguredProxyURL != auth.ProxyURL || response.Auth.EffectiveProxyURL != "direct" {
		t.Fatalf("auth proxy state = %#v, want configured proxy and direct effective", response.Auth)
	}
	if response.RuntimeOverride.Disabled == nil || response.RuntimeOverride.Priority == nil || response.RuntimeOverride.ProxyURL == nil {
		t.Fatalf("runtime override = %#v, want all fields", response.RuntimeOverride)
	}
	if !response.Applied || response.Revisions.Disabled != 1 || response.Revisions.Priority != 1 || response.Revisions.ProxyURL != 1 {
		t.Fatalf("runtime override revisions = %#v, applied=%v", response.Revisions, response.Applied)
	}
	if response.Auth.RuntimeOverrideRevisions != response.Revisions {
		t.Fatalf("auth revisions = %#v, response revisions = %#v", response.Auth.RuntimeOverrideRevisions, response.Revisions)
	}

	current, ok := host.currentAuthManager().GetByID(auth.ID)
	if !ok {
		t.Fatal("runtime auth disappeared")
	}
	if current.Disabled || current.ProxyURL != auth.ProxyURL || current.ConfiguredPriority() != 14 {
		t.Fatalf("configured auth changed = %#v", current)
	}
}

func TestHostAuthSetRuntimeOverrideCallbackClearsSelectedFields(t *testing.T) {
	auth := &coreauth.Auth{
		ID:       "antigravity-clear",
		Provider: "antigravity",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"priority":     "14",
			"runtime_only": "true",
		},
	}
	auth.EnsureIndex()
	host := New()
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	if _, errRegister := host.currentAuthManager().Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	disabled := true
	priority := 13
	if _, errSet := host.currentAuthManager().SetRuntimeAuthOverride(auth.Index, coreauth.RuntimeAuthOverride{
		Disabled: &disabled,
		Priority: &priority,
	}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}
	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex: auth.Index,
		Clear: []pluginapi.HostAuthRuntimeOverrideField{
			pluginapi.HostAuthRuntimeOverrideDisabled,
			pluginapi.HostAuthRuntimeOverridePriority,
		},
	})
	if errMarshal != nil {
		t.Fatalf("Marshal() error = %v", errMarshal)
	}

	rawResponse, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthSetRuntimeOverride, rawRequest)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthSetRuntimeOverrideResponse](rawResponse)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if response.Auth.EffectiveDisabled || response.Auth.EffectivePriority != 14 {
		t.Fatalf("auth effective state = %#v, want configured routing", response.Auth)
	}
	if response.RuntimeOverride.Disabled != nil || response.RuntimeOverride.Priority != nil {
		t.Fatalf("runtime override = %#v, want cleared fields", response.RuntimeOverride)
	}
}

func TestHostAuthSetRuntimeOverrideCallbackClearsAndSetsTogether(t *testing.T) {
	auth := &coreauth.Auth{
		ID:         "antigravity-patch",
		Provider:   "antigravity",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"priority": "14", "runtime_only": "true"},
	}
	host := New()
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	registered, errRegister := host.currentAuthManager().Register(context.Background(), auth)
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	disabled := true
	oldPriority := 13
	if _, errSet := host.currentAuthManager().SetRuntimeAuthOverride(registered.Index, coreauth.RuntimeAuthOverride{
		Disabled: &disabled,
		Priority: &oldPriority,
	}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}

	newPriority := 12
	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex: registered.Index,
		Priority:  &newPriority,
		Clear: []pluginapi.HostAuthRuntimeOverrideField{
			pluginapi.HostAuthRuntimeOverrideDisabled,
			pluginapi.HostAuthRuntimeOverridePriority,
		},
	})
	if errMarshal != nil {
		t.Fatalf("Marshal() error = %v", errMarshal)
	}
	rawResponse, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthSetRuntimeOverride, rawRequest)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthSetRuntimeOverrideResponse](rawResponse)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if response.Auth.EffectiveDisabled || response.Auth.EffectivePriority != newPriority {
		t.Fatalf("auth effective state = %#v, want enabled priority %d", response.Auth, newPriority)
	}
	if response.RuntimeOverride.Disabled != nil || response.RuntimeOverride.Priority == nil || *response.RuntimeOverride.Priority != newPriority {
		t.Fatalf("runtime override = %#v, want only priority %d", response.RuntimeOverride, newPriority)
	}
}

func TestHostAuthSetRuntimeOverrideRejectsDisabledFalse(t *testing.T) {
	disabled := false
	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex: "auth-index",
		Disabled:  &disabled,
	})
	if errMarshal != nil {
		t.Fatalf("Marshal() error = %v", errMarshal)
	}
	if _, errCall := New().callFromPlugin(context.Background(), pluginabi.MethodHostAuthSetRuntimeOverride, rawRequest); errCall == nil {
		t.Fatal("callFromPlugin() error = nil, want disabled=false rejection")
	}
}

func TestHostAuthSetRuntimeOverrideCASRejectsSameValueTakeover(t *testing.T) {
	auth := &coreauth.Auth{
		ID:         "antigravity-cas",
		Provider:   "antigravity",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"priority": "14", "runtime_only": "true"},
	}
	host := New()
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	registered, errRegister := host.currentAuthManager().Register(context.Background(), auth)
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	priority := 13
	call := func(request pluginapi.HostAuthSetRuntimeOverrideRequest) pluginapi.HostAuthSetRuntimeOverrideResponse {
		t.Helper()
		rawRequest, errMarshal := json.Marshal(request)
		if errMarshal != nil {
			t.Fatal(errMarshal)
		}
		rawResponse, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthSetRuntimeOverride, rawRequest)
		if errCall != nil {
			t.Fatalf("callFromPlugin() error = %v", errCall)
		}
		response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthSetRuntimeOverrideResponse](rawResponse)
		if errDecode != nil {
			t.Fatalf("decode response: %v", errDecode)
		}
		return response
	}

	first := call(pluginapi.HostAuthSetRuntimeOverrideRequest{AuthIndex: registered.Index, Priority: &priority})
	if !first.Applied || first.Revisions.Priority != 1 {
		t.Fatalf("first response = %#v", first)
	}
	second := call(pluginapi.HostAuthSetRuntimeOverrideRequest{AuthIndex: registered.Index, Priority: &priority})
	if !second.Applied || second.Revisions.Priority != 2 {
		t.Fatalf("same-value response = %#v", second)
	}

	staleRevision := first.Revisions.Priority
	stale := call(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex:       registered.Index,
		Clear:           []pluginapi.HostAuthRuntimeOverrideField{pluginapi.HostAuthRuntimeOverridePriority},
		IfRevision:      &staleRevision,
		IfRevisionField: pluginapi.HostAuthRuntimeOverridePriority,
	})
	if stale.Applied || stale.Revision != 2 || stale.Revisions.Priority != 2 {
		t.Fatalf("stale response = %#v", stale)
	}
	if stale.RuntimeOverride.Priority == nil || *stale.RuntimeOverride.Priority != priority {
		t.Fatalf("stale CAS changed runtime override: %#v", stale.RuntimeOverride)
	}
}

func TestHostAuthSetRuntimeOverrideMultiFieldCASIsAtomic(t *testing.T) {
	auth := &coreauth.Auth{
		ID:         "antigravity-multi-cas",
		Provider:   "antigravity",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"priority": "14", "runtime_only": "true"},
	}
	host := New()
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	registered, errRegister := host.currentAuthManager().Register(context.Background(), auth)
	if errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	disabled := true
	priority := 13
	if _, errSet := host.currentAuthManager().SetRuntimeAuthOverride(registered.Index, coreauth.RuntimeAuthOverride{
		Priority: &priority,
	}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}

	call := func(request pluginapi.HostAuthSetRuntimeOverrideRequest) pluginapi.HostAuthSetRuntimeOverrideResponse {
		t.Helper()
		rawRequest, errMarshal := json.Marshal(request)
		if errMarshal != nil {
			t.Fatal(errMarshal)
		}
		rawResponse, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthSetRuntimeOverride, rawRequest)
		if errCall != nil {
			t.Fatalf("callFromPlugin() error = %v", errCall)
		}
		response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthSetRuntimeOverrideResponse](rawResponse)
		if errDecode != nil {
			t.Fatalf("decode response: %v", errDecode)
		}
		return response
	}

	newPriority := 12
	staleRevisions := pluginapi.HostAuthRuntimeOverrideRevisions{Disabled: 0, Priority: 0}
	stale := call(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex:   registered.Index,
		Disabled:    &disabled,
		Priority:    &newPriority,
		IfRevisions: &staleRevisions,
	})
	if stale.Applied || stale.Revisions.Disabled != 0 || stale.Revisions.Priority != 1 {
		t.Fatalf("stale multi-field response = %#v", stale)
	}
	if stale.RuntimeOverride.Disabled != nil || stale.RuntimeOverride.Priority == nil || *stale.RuntimeOverride.Priority != priority {
		t.Fatalf("stale multi-field patch partially applied: %#v", stale.RuntimeOverride)
	}

	currentRevisions := pluginapi.HostAuthRuntimeOverrideRevisions{Disabled: 0, Priority: 1, ProxyURL: 99}
	current := call(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex:   registered.Index,
		Disabled:    &disabled,
		Priority:    &newPriority,
		IfRevisions: &currentRevisions,
	})
	if !current.Applied || current.Revisions.Disabled != 1 || current.Revisions.Priority != 2 || current.Revisions.ProxyURL != 0 {
		t.Fatalf("current multi-field response = %#v", current)
	}
	if !current.Auth.EffectiveDisabled || current.Auth.EffectivePriority != newPriority {
		t.Fatalf("current multi-field auth state = %#v", current.Auth)
	}
}

func TestHostAuthSetRuntimeOverrideRejectsMixedRevisionGuards(t *testing.T) {
	revision := uint64(0)
	revisions := pluginapi.HostAuthRuntimeOverrideRevisions{}
	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex:       "auth-index",
		Priority:        new(int),
		IfRevision:      &revision,
		IfRevisionField: pluginapi.HostAuthRuntimeOverridePriority,
		IfRevisions:     &revisions,
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if _, errCall := New().callFromPlugin(context.Background(), pluginabi.MethodHostAuthSetRuntimeOverride, rawRequest); errCall == nil {
		t.Fatal("callFromPlugin() error = nil, want mixed revision guard rejection")
	}
}

func TestHostAuthSetRuntimeOverrideRequiresRevisionField(t *testing.T) {
	revision := uint64(0)
	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthSetRuntimeOverrideRequest{
		AuthIndex:  "auth-index",
		Priority:   new(int),
		IfRevision: &revision,
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if _, errCall := New().callFromPlugin(context.Background(), pluginabi.MethodHostAuthSetRuntimeOverride, rawRequest); errCall == nil {
		t.Fatal("callFromPlugin() error = nil, want if_revision_field validation error")
	}
}
