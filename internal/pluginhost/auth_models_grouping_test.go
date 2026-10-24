package pluginhost

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestGroupingAuthModelsFiltersCredentialsAndModels(t *testing.T) {
	host, allowed, scope, callbackID, caller := groupingCallbackFixture(t)
	blocked := registerGroupingModelCredential(t, host, "blocked-model-credential", false)
	disabled := registerGroupingModelCredential(t, host, "disabled-model-credential", true)
	scope.allowed[disabled.ID] = true
	registerGroupingModels(t, allowed)
	for _, index := range []string{"", allowed.Index} {
		response := queryGroupingAuthModels(t, host, caller, callbackID, index)
		if len(response.Credentials) != 1 || response.Credentials[0].ID != allowed.ID {
			t.Fatalf("unexpected credential visibility: %+v", response.Credentials)
		}
		models := response.Credentials[0].Models
		if len(models) != 1 || models[0] != allowed.ID+"-model" {
			t.Fatalf("unexpected models: %v", models)
		}
	}
	for _, auth := range []*coreauth.Auth{blocked, disabled} {
		_, errCall := host.callFromPlugin(caller, pluginabi.MethodHostAuthModels, authModelsGroupingPayload(t, callbackID, auth.Index))
		if !coreauth.IsCredentialAccessError(errCall) {
			t.Fatalf("credential %s was exposed: %v", auth.ID, errCall)
		}
	}
}

func TestGroupingAuthModelsRechecksRevocationBeforeReturning(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		host, allowed, scope, callbackID, caller := groupingCallbackFixture(t)
		scope.revokeAfter = 1
		index := ""
		if explicit {
			index = allowed.Index
		}
		raw, errCall := host.callFromPlugin(caller, pluginabi.MethodHostAuthModels, authModelsGroupingPayload(t, callbackID, index))
		if !coreauth.IsCredentialAccessError(errCall) || len(raw) != 0 {
			t.Fatalf("revoked model query exposed data: %s, %v", raw, errCall)
		}
	}
}

func TestGroupingAuthModelsPolicyTransitionsRemainFailClosed(t *testing.T) {
	host, allowed, scope, callbackID, caller := groupingCallbackFixture(t)
	registerGroupingModelCredential(t, host, "unbound-model-credential", false)
	manager := host.currentAuthManager()
	manager.SetCredentialAccessPolicy(nil)
	if got := queryGroupingAuthModels(t, host, context.Background(), "", ""); len(got.Credentials) != 2 {
		t.Fatal("disabled policy changed legacy model enumeration")
	}
	host.runtimeConfig = &config.Config{Grouping: config.GroupingConfig{Enabled: true}}
	request := authModelsGroupingPayload(t, callbackID, "")
	if _, errCall := host.callFromPlugin(caller, pluginabi.MethodHostAuthModels, request); !coreauth.IsCredentialAccessError(errCall) {
		t.Fatalf("enabled grouping without policy exposed models: %v", errCall)
	}
	manager.SetCredentialAccessPolicy(groupingCallbackPolicy{scope: scope})
	got := queryGroupingAuthModels(t, host, caller, callbackID, "")
	if len(got.Credentials) != 1 || got.Credentials[0].ID != allowed.ID {
		t.Fatal("enabling policy did not narrow model visibility")
	}
	if _, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthModels, request); !coreauth.IsCredentialAccessError(errCall) {
		t.Fatalf("callback borrowed another plugin's identity: %v", errCall)
	}
	host.runtimeConfig = &config.Config{}
	manager.SetCredentialAccessPolicy(nil)
	if got := queryGroupingAuthModels(t, host, context.Background(), "", ""); len(got.Credentials) != 2 {
		t.Fatal("disabling grouping did not restore legacy model visibility")
	}
}

func registerGroupingModelCredential(t *testing.T, host *Host, id string, disabled bool) *coreauth.Auth {
	t.Helper()
	auth, errRegister := host.currentAuthManager().Register(context.Background(), &coreauth.Auth{
		ID: id, Provider: "demo", Disabled: disabled, Attributes: map[string]string{"runtime_only": "true"},
	})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	registerGroupingModels(t, auth)
	return auth
}

func registerGroupingModels(t *testing.T, auth *coreauth.Auth) {
	t.Helper()
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: auth.ID + "-model"}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
}

func queryGroupingAuthModels(t *testing.T, host *Host, caller context.Context, callbackID, index string) pluginapi.HostAuthModelsResponse {
	t.Helper()
	raw, errCall := host.callFromPlugin(caller, pluginabi.MethodHostAuthModels, authModelsGroupingPayload(t, callbackID, index))
	if errCall != nil {
		t.Fatal(errCall)
	}
	response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthModelsResponse](raw)
	if errDecode != nil {
		t.Fatal(errDecode)
	}
	return response
}

func authModelsGroupingPayload(t *testing.T, callbackID, index string) []byte {
	t.Helper()
	raw, errMarshal := json.Marshal(pluginapi.HostAuthModelsRequest{AuthIndex: index, HostCallbackID: callbackID})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	return raw
}
