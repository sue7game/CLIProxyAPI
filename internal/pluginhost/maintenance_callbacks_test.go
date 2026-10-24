package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type maintenanceLifecycleClient struct {
	instance hostCallbackInstance
	last     rpcLifecycleRequest
	call     func(rpcLifecycleRequest) error
}

func (c *maintenanceLifecycleClient) callbackInstance() *hostCallbackInstance { return &c.instance }
func (c *maintenanceLifecycleClient) Shutdown()                               {}
func (c *maintenanceLifecycleClient) Call(_ context.Context, _ string, raw []byte) ([]byte, error) {
	c.last = rpcLifecycleRequest{}
	if err := json.Unmarshal(raw, &c.last); err != nil {
		return nil, err
	}
	if c.call != nil {
		if err := c.call(c.last); err != nil {
			return nil, err
		}
	}
	return marshalRPCResult(rpcRegistration{SchemaVersion: pluginabi.SchemaVersion})
}

type maintenanceTestPolicy struct{}
type maintenanceTestScope struct{}

func (maintenanceTestPolicy) BeginAttempt(ctx context.Context) (coreauth.CredentialAccessScope, error) {
	if _, trusted := access.InternalOperationFromContext(ctx); !trusted {
		return nil, errors.New("missing trusted internal operation")
	}
	return maintenanceTestScope{}, nil
}
func (maintenanceTestScope) Allows(auth *coreauth.Auth) bool                    { return auth != nil }
func (maintenanceTestScope) AuthorizeUse(context.Context, *coreauth.Auth) error { return nil }

func maintenanceFixture(t *testing.T) (*Host, *maintenanceLifecycleClient, *coreauth.Auth, context.Context) {
	t.Helper()
	host, auth := newHostAuthRequestTestHost(t, &coreauth.Auth{ID: "maintenance-auth", Provider: "demo", Attributes: map[string]string{"runtime_only": "true"}})
	host.currentAuthManager().SetCredentialAccessPolicy(maintenanceTestPolicy{})
	client := &maintenanceLifecycleClient{}
	caller := withHostCallbackIdentity(context.Background(), "maintenance-plugin", &client.instance)
	t.Cleanup(client.instance.revokeMaintenanceCallback)
	return host, client, auth, caller
}

func maintenanceRegister(t *testing.T, host *Host, client *maintenanceLifecycleClient, enabled bool) rpcLifecycleRequest {
	t.Helper()
	raw := []byte("enabled: false\n")
	if enabled {
		raw = []byte("enabled: true\n")
	}
	if _, err := registerRPCPlugin(context.Background(), host, "maintenance-plugin", client, pluginabi.MethodPluginReconfigure, raw); err != nil {
		t.Fatal(err)
	}
	return client.last
}

func maintenancePayload(t *testing.T, id, authIndex string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"host_callback_id": id, "auth_index": authIndex})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMaintenanceCallbackBoundedMethodsAndInstanceIdentity(t *testing.T) {
	host, client, auth, caller := maintenanceFixture(t)
	lifecycle := maintenanceRegister(t, host, client, true)
	if lifecycle.HostCallbackID == "" || lifecycle.MaintenanceCallbackID == "" || lifecycle.HostCallbackID == lifecycle.MaintenanceCallbackID {
		t.Fatal("lifecycle and maintenance scopes must be distinct nonempty capabilities")
	}
	for _, id := range []string{"", "forged", lifecycle.HostCallbackID} {
		if _, err := host.callFromPlugin(caller, pluginabi.MethodHostAuthList, maintenancePayload(t, id, auth.Index)); !coreauth.IsCredentialAccessError(err) {
			t.Fatalf("missing/forged/expired scope %q accepted: %v", id, err)
		}
	}
	request := maintenancePayload(t, lifecycle.MaintenanceCallbackID, auth.Index)
	for _, other := range []context.Context{context.Background(), withHostCallbackIdentity(context.Background(), "other", &client.instance), withHostCallbackIdentity(context.Background(), "maintenance-plugin", &hostCallbackInstance{})} {
		if _, err := host.callFromPlugin(other, pluginabi.MethodHostAuthList, request); !coreauth.IsCredentialAccessError(err) {
			t.Fatalf("foreign caller accepted: %v", err)
		}
	}
	for _, method := range []string{pluginabi.MethodHostModelExecute, pluginabi.MethodHostModelExecuteStream, pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPOperationOpen, pluginabi.MethodHostAuthModels, pluginabi.MethodHostAuthSave, pluginabi.MethodHostRoutingResetCooldown, pluginabi.MethodHostAffinityLookup} {
		if _, err := host.callFromPlugin(caller, method, request); !coreauth.IsCredentialAccessError(err) {
			t.Fatalf("maintenance capability accepted forbidden callback %s: %v", method, err)
		}
	}
	if _, err := host.callFromPlugin(caller, pluginabi.MethodHostAuthGetRuntime, request); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceMetadataIncludesDisabledButHTTPRemainsDenied(t *testing.T) {
	host, client, auth, caller := maintenanceFixture(t)
	id := maintenanceRegister(t, host, client, true).MaintenanceCallbackID
	disabled := true
	raw, err := json.Marshal(pluginapi.HostAuthSetRuntimeOverrideRequest{HostCallbackID: id, AuthIndex: auth.Index, Disabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = host.callFromPlugin(caller, pluginabi.MethodHostAuthSetRuntimeOverride, raw); err != nil {
		t.Fatal(err)
	}
	raw, err = host.callFromPlugin(caller, pluginabi.MethodHostAuthList, maintenancePayload(t, id, ""))
	if err != nil {
		t.Fatal(err)
	}
	response, err := decodeRPCEnvelope[rpcHostAuthListResponse](raw)
	if err != nil || len(response.Files) != 1 || !response.Files[0].EffectiveDisabled {
		t.Fatalf("disabled maintenance metadata missing: %+v, %v", response, err)
	}
	request := authRequestLifecyclePayload(t, auth.Index, id)
	if _, err = host.callFromPlugin(caller, pluginabi.MethodHostAuthRequest, request); !coreauth.IsCredentialAccessError(err) {
		t.Fatalf("disabled credential network use accepted: %v", err)
	}
}

func TestMaintenanceDisableRevokesImmediatelyAndCleanupScopeExpires(t *testing.T) {
	host, client, auth, caller := maintenanceFixture(t)
	old := maintenanceRegister(t, host, client, true).MaintenanceCallbackID
	_, operation, opened := host.httpOperations.open("maintenance-plugin", &client.instance, old, context.Background())
	if !opened || !host.addCallbackCleanup(old, operation.cancel) {
		t.Fatal("could not attach cancellable maintenance operation")
	}
	client.call = func(request rpcLifecycleRequest) error {
		if request.MaintenanceCallbackID != "" || operation.ctx.Err() == nil {
			t.Fatal("disabled lifecycle retained background maintenance")
		}
		if _, err := host.callFromPlugin(caller, pluginabi.MethodHostAuthList, maintenancePayload(t, old, "")); !coreauth.IsCredentialAccessError(err) {
			t.Fatalf("old maintenance scope survived disable: %v", err)
		}
		_, err := host.callFromPlugin(caller, pluginabi.MethodHostAuthList, maintenancePayload(t, request.HostCallbackID, auth.Index))
		return err
	}
	lifecycle := maintenanceRegister(t, host, client, false)
	if _, err := host.callFromPlugin(caller, pluginabi.MethodHostAuthList, maintenancePayload(t, lifecycle.HostCallbackID, "")); !coreauth.IsCredentialAccessError(err) {
		t.Fatalf("cleanup capability survived lifecycle return: %v", err)
	}
}

func TestMaintenanceFailureAndRollbackReissueIndependentCapability(t *testing.T) {
	host, client, _, caller := maintenanceFixture(t)
	original := maintenanceRegister(t, host, client, true).MaintenanceCallbackID
	client.call = func(rpcLifecycleRequest) error { return errors.New("cleanup failed") }
	if _, err := registerRPCPlugin(context.Background(), host, "maintenance-plugin", client, pluginabi.MethodPluginReconfigure, []byte("enabled: false\n")); err == nil {
		t.Fatal("cleanup failure was swallowed")
	}
	client.call = nil
	restored := maintenanceRegister(t, host, client, true).MaintenanceCallbackID
	if restored == original {
		t.Fatal("rollback reused revoked maintenance capability")
	}
	if _, err := host.callFromPlugin(caller, pluginabi.MethodHostAuthList, maintenancePayload(t, original, "")); !coreauth.IsCredentialAccessError(err) {
		t.Fatalf("old capability became reusable after rollback: %v", err)
	}
	if _, err := host.callFromPlugin(caller, pluginabi.MethodHostAuthList, maintenancePayload(t, restored, "")); err != nil {
		t.Fatal(err)
	}
	host.closeHostHTTPCallbackInstance("maintenance-plugin", &client.instance)
	if _, _, _, exists := host.lookupCallbackContext(restored); exists {
		t.Fatal("closing instance retained maintenance callback")
	}
}

func TestMaintenanceFailedRegistrationRevokesIssuedCapability(t *testing.T) {
	host, client, _, _ := maintenanceFixture(t)
	client.call = func(rpcLifecycleRequest) error { return errors.New("registration failed") }
	if _, err := registerRPCPlugin(context.Background(), host, "maintenance-plugin", client, pluginabi.MethodPluginRegister, []byte("enabled: true\n")); err == nil {
		t.Fatal("registration failure was swallowed")
	}
	if client.last.MaintenanceCallbackID == "" {
		t.Fatal("test did not receive maintenance capability")
	}
	if _, _, _, exists := host.lookupCallbackContext(client.last.MaintenanceCallbackID); exists {
		t.Fatal("failed registration retained maintenance callback")
	}
}
