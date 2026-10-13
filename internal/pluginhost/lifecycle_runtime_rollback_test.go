package pluginhost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestHotReloadRuntimeCleanupInterruptedBeforeCommitRestoresRuntime(t *testing.T) {
	for _, interruption := range []string{"cancel", "loading_request_changed"} {
		t.Run(interruption, func(t *testing.T) {
			host, old, cfg, authID := runtimeRollbackFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			interruptAfterCleanup(host, interruption, cancel)
			host.ApplyConfig(ctx, cfg)
			assertRuntimeRollback(t, host, old, authID)
		})
	}
}

func runtimeRollbackFixture(t *testing.T) (*Host, *loadedPlugin, *config.Config, string) {
	t.Helper()
	oldClient := &retryDeactivationClient{registration: validTestPlugin("alpha")}
	betaClient := &retryDeactivationClient{registration: validTestPlugin("beta")}
	newClient := &retryDeactivationClient{registration: validTestPlugin("alpha")}
	host := NewForTest(&sequencePluginLoader{clients: []pluginClient{oldClient, betaClient, newClient}})
	t.Cleanup(host.ShutdownAll)
	clearRequest, authID := deactivationRuntimeOverride(t, host)
	dir, _ := makeVersionedPluginDir(t, "alpha", "1.0.0")
	writeVersionedPluginFile(t, dir, "beta", "1.0.0")
	cfg := versionedPluginHostConfig(t, dir, "1.0.0")
	cfg.Plugins.Configs["beta"] = enabledPluginConfigWithStoreVersion(t, "1.0.0")
	host.ApplyConfig(context.Background(), cfg)
	callbackCtx, instance := markRuntimeCleanupOwner(t, host, clearRequest)
	oldClient.onDeactivate = runtimeCleanupCallback(t, host, callbackCtx, instance, clearRequest, false)
	old := host.loaded["alpha"]
	installRollbackRuntimeState(host, old)
	installRollbackRuntimeState(host, host.loaded["beta"])
	writeVersionedPluginFile(t, dir, "alpha", "2.0.0")
	cfg.Plugins.Configs["alpha"] = enabledPluginConfigWithStoreVersion(t, "2.0.0")
	return host, old, cfg, authID
}

func interruptAfterCleanup(host *Host, interruption string, cancel context.CancelFunc) {
	loaded := host.loaded["alpha"]
	interrupted := false
	loaded.client = &afterLifecycleCallClient{pluginClient: loaded.client, afterCall: func(method string) {
		if method != pluginabi.MethodPluginReconfigure || interrupted {
			return
		}
		interrupted = true
		if interruption == "cancel" {
			cancel()
			return
		}
		host.mu.Lock()
		delete(host.loading, "alpha")
		host.mu.Unlock()
	}}
}

type afterLifecycleCallClient struct {
	pluginClient
	afterCall func(string)
}

func (c *afterLifecycleCallClient) Call(ctx context.Context, method string, request []byte) ([]byte, error) {
	response, errCall := c.pluginClient.Call(ctx, method, request)
	if errCall == nil {
		// Run after the guarded call succeeds, without racing its cancellation select.
		c.afterCall(method)
	}
	return response, errCall
}

func installRollbackRuntimeState(host *Host, loaded *loadedPlugin) {
	id := loaded.id
	handler := managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
		return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Body: []byte(id)}, nil
	})
	host.mu.Lock()
	defer host.mu.Unlock()
	managementPath := "/v0/management/" + id
	resourcePath := "/v0/resource/plugins/" + id + "/dashboard"
	host.managementRoutes[managementRouteKey(http.MethodGet, managementPath)] = managementRouteRecord{
		pluginID: id, path: loaded.path, version: loaded.version,
		route: pluginapi.ManagementRoute{Method: http.MethodGet, Path: managementPath, Handler: handler},
	}
	host.resourceRoutes[managementRouteKey(http.MethodGet, resourcePath)] = resourceRouteRecord{
		pluginID: id, path: loaded.path, version: loaded.version,
		route: pluginapi.ResourceRoute{Path: resourcePath, Handler: handler},
	}
	host.commandLineFlags[id] = commandLineFlagRecord{pluginID: id, value: id, set: true}
	host.commandLineHits[id] = struct{}{}
	host.modelProviders[id] = id
	host.modelRegistrations[id] = pluginModelRegistration{pluginID: id, provider: id}
	host.providerModels[id] = []*registryModelInfo{{ID: id}}
}

func assertRuntimeRollback(t *testing.T, host *Host, old *loadedPlugin, authID string) {
	t.Helper()
	if old.callbackInstance.closed.Load() || !host.PluginRegistered("alpha") || host.pluginDeactivationPending("alpha") {
		t.Fatal("interrupted replacement did not restore the active old instance")
	}
	if !host.pluginIdentityCurrent("alpha", old.path, old.version) {
		t.Fatal("interrupted replacement did not restore old identity maps")
	}
	auth, ok := host.currentAuthManager().GetByID(authID)
	if !ok || !auth.RuntimeAuthOverride().Empty() {
		t.Fatal("replacement interruption did not happen after runtime cleanup succeeded")
	}
	records := host.activeRecords()
	if len(records) != 2 {
		t.Fatalf("rollback has %d capability records, want both plugins", len(records))
	}
	for _, id := range []string{"alpha", "beta"} {
		if !host.PluginRegistered(id) {
			t.Fatalf("rollback lost plugin %s", id)
		}
		assertRollbackRoutes(t, host, id)
		assertRollbackStateMaps(t, host, id)
	}
}

func assertRollbackRoutes(t *testing.T, host *Host, id string) {
	t.Helper()
	for path, serve := range map[string]func(http.ResponseWriter, *http.Request) bool{
		"/v0/management/" + id:                      host.ServeManagementHTTP,
		"/v0/resource/plugins/" + id + "/dashboard": host.ServeResourceHTTP,
	} {
		response := httptest.NewRecorder()
		if !serve(response, httptest.NewRequest(http.MethodGet, path, nil)) || response.Code != http.StatusOK || response.Body.String() != id {
			t.Fatalf("rollback did not restore route %s: status=%d body=%q", path, response.Code, response.Body.String())
		}
	}
}

func assertRollbackStateMaps(t *testing.T, host *Host, id string) {
	t.Helper()
	host.mu.Lock()
	defer host.mu.Unlock()
	if flag, ok := host.commandLineFlags[id]; !ok || flag.pluginID != id || flag.value != id || !flag.set {
		t.Fatalf("rollback lost command-line state for %s", id)
	}
	if _, hit := host.commandLineHits[id]; !hit {
		t.Fatalf("rollback lost command-line hit for %s", id)
	}
	if host.modelProviders[id] != id || host.modelRegistrations[id].provider != id {
		t.Fatalf("rollback lost model registration for %s", id)
	}
	if models := host.providerModels[id]; len(models) != 1 || models[0].ID != id {
		t.Fatalf("rollback lost provider models for %s", id)
	}
}
