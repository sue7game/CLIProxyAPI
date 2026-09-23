package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

func TestHostApplyConfigDeactivatesAndReactivatesLoadedPlugin(t *testing.T) {
	loader := newTestSymbolLoader()
	plugin := &testPlugin{registerResult: validTestPlugin("alpha")}
	lookup := newTestSymbolLookup(plugin)
	var lifecycleEnabled []bool
	lookup.reconfigureOverride = func(raw []byte) pluginapi.Plugin {
		lifecycleEnabled = append(lifecycleEnabled, decodeLifecycleEnabled(t, raw))
		return validTestPlugin("alpha")
	}
	loader.lookups["alpha"] = lookup
	host := NewForTest(loader)
	t.Cleanup(host.ShutdownAll)
	pluginsDir := makePluginDir(t, "alpha")

	host.ApplyConfig(context.Background(), pluginHostConfig(pluginsDir, true, true))
	host.ApplyConfig(context.Background(), pluginHostConfig(pluginsDir, true, false))

	if len(lifecycleEnabled) != 1 || lifecycleEnabled[0] {
		t.Fatalf("deactivation lifecycle enabled values = %#v, want [false]", lifecycleEnabled)
	}
	if host.PluginRegistered("alpha") {
		t.Fatal("PluginRegistered(alpha) = true after deactivation")
	}
	if !host.PluginLoaded("alpha") {
		t.Fatal("PluginLoaded(alpha) = false after deactivation")
	}
	if lookup.shutdownCalls != 0 {
		t.Fatalf("shutdown calls after deactivation = %d, want 0", lookup.shutdownCalls)
	}

	host.ApplyConfig(context.Background(), pluginHostConfig(pluginsDir, true, true))

	if len(lifecycleEnabled) != 2 || !lifecycleEnabled[1] {
		t.Fatalf("reactivation lifecycle enabled values = %#v, want [false true]", lifecycleEnabled)
	}
	if !host.PluginRegistered("alpha") {
		t.Fatal("PluginRegistered(alpha) = false after reactivation")
	}
	if loader.openCalls != 1 {
		t.Fatalf("Open calls = %d, want 1 while reusing the loaded client", loader.openCalls)
	}
}

func TestHostApplyConfigGloballyDisabledDeactivatesWithoutResolvingDirectory(t *testing.T) {
	loader := newTestSymbolLoader()
	plugin := &testPlugin{registerResult: validTestPlugin("alpha")}
	lookup := newTestSymbolLookup(plugin)
	var lifecycleEnabled []bool
	lookup.reconfigureOverride = func(raw []byte) pluginapi.Plugin {
		lifecycleEnabled = append(lifecycleEnabled, decodeLifecycleEnabled(t, raw))
		return validTestPlugin("alpha")
	}
	loader.lookups["alpha"] = lookup
	host := NewForTest(loader)
	t.Cleanup(host.ShutdownAll)

	host.ApplyConfig(context.Background(), pluginHostConfig(makePluginDir(t, "alpha"), true, true))
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	host.ApplyConfig(context.Background(), &config.Config{
		Plugins: config.PluginsConfig{Enabled: false, Dir: "~/.cli-proxy-api/plugins"},
	})

	if len(lifecycleEnabled) != 1 || lifecycleEnabled[0] {
		t.Fatalf("global deactivation lifecycle enabled values = %#v, want [false]", lifecycleEnabled)
	}
	if snapshot := host.Snapshot(); snapshot.enabled || len(snapshot.records) != 0 {
		t.Fatalf("Snapshot() = %+v, want globally disabled empty snapshot", snapshot)
	}
	if !host.PluginLoaded("alpha") {
		t.Fatal("PluginLoaded(alpha) = false after global deactivation")
	}
	if lookup.shutdownCalls != 0 {
		t.Fatalf("shutdown calls after global deactivation = %d, want 0", lookup.shutdownCalls)
	}
}

func TestHostApplyConfigDetachesSnapshotBeforePluginDeactivationReturns(t *testing.T) {
	loader := newTestSymbolLoader()
	plugin := &testPlugin{registerResult: validTestPlugin("alpha")}
	lookup := newTestSymbolLookup(plugin)
	deactivationStarted := make(chan struct{})
	releaseDeactivation := make(chan struct{})
	var releaseOnce sync.Once
	lookup.reconfigureOverride = func(raw []byte) pluginapi.Plugin {
		if decodeLifecycleEnabled(t, raw) {
			return validTestPlugin("alpha")
		}
		close(deactivationStarted)
		<-releaseDeactivation
		return validTestPlugin("alpha")
	}
	loader.lookups["alpha"] = lookup
	host := NewForTest(loader)
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseDeactivation) })
		host.ShutdownAll()
	})
	pluginsDir := makePluginDir(t, "alpha")
	host.ApplyConfig(context.Background(), pluginHostConfig(pluginsDir, true, true))

	applyDone := make(chan struct{})
	go func() {
		host.ApplyConfig(context.Background(), pluginHostConfig(pluginsDir, true, false))
		close(applyDone)
	}()
	waitForHostTestSignal(t, deactivationStarted, "plugin deactivation")

	if host.PluginRegistered("alpha") {
		t.Fatal("PluginRegistered(alpha) remained true while deactivation was blocked")
	}
	if records := host.activeRecords(); len(records) != 0 {
		t.Fatalf("active records while deactivation was blocked = %d, want 0", len(records))
	}
	releaseOnce.Do(func() { close(releaseDeactivation) })
	waitForHostTestSignal(t, applyDone, "deactivation ApplyConfig completion")
}

func TestHostApplyConfigRetriesFailedPluginDeactivation(t *testing.T) {
	client := &retryDeactivationClient{registration: validTestPlugin("alpha")}
	host := NewForTest(&countingPluginLoader{client: client})
	t.Cleanup(host.ShutdownAll)
	pluginsDir := makePluginDir(t, "alpha")
	host.ApplyConfig(context.Background(), pluginHostConfig(pluginsDir, true, true))

	host.ApplyConfig(context.Background(), pluginHostConfig(pluginsDir, true, false))
	if calls := client.deactivationCallCount(); calls != 1 {
		t.Fatalf("deactivation calls after first failure = %d, want 1", calls)
	}
	host.mu.Lock()
	pending := len(host.deactivationPending)
	host.mu.Unlock()
	if pending != 1 {
		t.Fatalf("pending deactivations after failure = %d, want 1", pending)
	}

	host.ApplyConfig(context.Background(), pluginHostConfig(pluginsDir, true, false))
	if calls := client.deactivationCallCount(); calls != 2 {
		t.Fatalf("deactivation calls after retry = %d, want 2", calls)
	}
	host.mu.Lock()
	pending = len(host.deactivationPending)
	host.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending deactivations after successful retry = %d, want 0", pending)
	}
}

func pluginHostConfig(dir string, globalEnabled, itemEnabled bool) *config.Config {
	return &config.Config{
		Plugins: config.PluginsConfig{
			Enabled: globalEnabled,
			Dir:     dir,
			Configs: map[string]config.PluginInstanceConfig{
				"alpha": {Enabled: &itemEnabled},
			},
		},
	}
}

func decodeLifecycleEnabled(t *testing.T, raw []byte) bool {
	t.Helper()
	var value struct {
		Enabled bool `yaml:"enabled"`
	}
	if errDecode := yaml.Unmarshal(raw, &value); errDecode != nil {
		t.Errorf("decode lifecycle config: %v", errDecode)
		return false
	}
	return value.Enabled
}

type retryDeactivationClient struct {
	mu                sync.Mutex
	registration      pluginapi.Plugin
	deactivationCalls int
}

func (c *retryDeactivationClient) Call(_ context.Context, method string, request []byte) ([]byte, error) {
	if method != pluginabi.MethodPluginRegister && method != pluginabi.MethodPluginReconfigure {
		return nil, fmt.Errorf("unexpected plugin method %s", method)
	}
	var lifecycle rpcLifecycleRequest
	if errDecode := json.Unmarshal(request, &lifecycle); errDecode != nil {
		return nil, errDecode
	}
	var configValue struct {
		Enabled bool `yaml:"enabled"`
	}
	if errDecode := yaml.Unmarshal(lifecycle.ConfigYAML, &configValue); errDecode != nil {
		return nil, errDecode
	}
	if method == pluginabi.MethodPluginReconfigure && !configValue.Enabled {
		c.mu.Lock()
		c.deactivationCalls++
		call := c.deactivationCalls
		c.mu.Unlock()
		if call == 1 {
			return nil, fmt.Errorf("temporary deactivation failure")
		}
	}
	return marshalRPCResult(rpcRegistration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata:      c.registration.Metadata,
		Capabilities:  rpcCapabilitiesFromPlugin(c.registration),
	})
}

func (c *retryDeactivationClient) Shutdown() {}

func (c *retryDeactivationClient) deactivationCallCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deactivationCalls
}
