package pluginhost

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestHostAuthSaveMultiAuthPreservesRuntimeOverridesAndRemovesStaleChildren(t *testing.T) {
	children := []string{"save-stable", "save-removed"}
	host := multiAuthSaveRuntimeHost(t, &children)
	manager := host.currentAuthManager()
	path := saveMultiAuthRuntimeFile(t, host)
	stable, _ := manager.GetByID(children[0])
	removed, _ := manager.GetByID(children[1])
	if stable == nil || removed == nil {
		t.Fatal("initial multi-auth save did not register both children")
	}
	disabled, proxy := true, "direct"
	override := coreauth.RuntimeAuthOverride{Disabled: &disabled, ProxyURL: &proxy}
	for _, auth := range []*coreauth.Auth{stable, removed} {
		if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, override); errSet != nil {
			t.Fatalf("set runtime override for %s: %v", auth.ID, errSet)
		}
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(removed.ID, "demo", []*registry.ModelInfo{{ID: "save-model"}})
	t.Cleanup(func() { reg.UnregisterClient(removed.ID) })
	children = []string{"save-stable", "save-new"}
	saveMultiAuthRuntimeFile(t, host)
	current, _ := manager.GetByID(stable.ID)
	if current == nil || current.Index != stable.Index || !current.EffectiveDisabled() || current.EffectiveProxyURL() != proxy {
		t.Fatal("multi-auth save lost the retained child's runtime override or auth index")
	}
	if revisions := current.RuntimeAuthOverrideRevisions(); revisions.Disabled != 1 || revisions.ProxyURL != 1 {
		t.Fatalf("runtime revisions = %#v, want original revisions", revisions)
	}
	assertRemovedSaveChild(t, manager, removed)
	added, _ := manager.GetByID("save-new")
	if added == nil || !added.RuntimeAuthOverride().Empty() {
		t.Fatal("new child inherited a removed child's runtime override")
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read saved multi-auth file: %v", errRead)
	}
	if strings.Contains(string(raw), "direct") || strings.Contains(string(raw), "runtime_override") {
		t.Fatalf("saved file contains runtime-only routing state: %s", raw)
	}
}

func assertRemovedSaveChild(t *testing.T, manager *coreauth.Manager, removed *coreauth.Auth) {
	t.Helper()
	if _, exists := manager.GetByID(removed.ID); exists {
		t.Fatal("stale same-file auth remained registered")
	}
	if len(registry.GetGlobalRegistry().GetModelsForClient(removed.ID)) != 0 {
		t.Fatal("stale same-file auth retained model registrations")
	}
	if _, errClear := manager.ClearRuntimeAuthOverride(removed.Index); errClear == nil {
		t.Fatal("removed child still accepted runtime override writes")
	}
}

func multiAuthSaveRuntimeHost(t *testing.T, children *[]string) *Host {
	t.Helper()
	provider := fakeAuthProvider{
		identifier: "demo",
		parseAuth: func(_ context.Context, _ pluginapi.AuthParseRequest) (pluginapi.AuthParseResponse, error) {
			auths := make([]pluginapi.AuthData, 0, len(*children))
			for _, id := range *children {
				auths = append(auths, pluginapi.AuthData{ID: id, Provider: "demo", FileName: "multi.json"})
			}
			return pluginapi.AuthParseResponse{Handled: true, Auths: auths}, nil
		},
	}
	host := newHostWithRecords(capabilityRecord{
		id:     "multi-save-plugin",
		plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{AuthProvider: provider}},
	})
	host.runtimeConfig = &config.Config{AuthDir: t.TempDir()}
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))
	return host
}

func saveMultiAuthRuntimeFile(t *testing.T, host *Host) string {
	t.Helper()
	request, errMarshal := json.Marshal(pluginapi.HostAuthSaveRequest{
		Name: "multi.json", JSON: json.RawMessage(`{"type":"demo","disabled":false}`),
	})
	if errMarshal != nil {
		t.Fatalf("marshal multi-auth save: %v", errMarshal)
	}
	raw, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostAuthSave, request)
	if errCall != nil {
		t.Fatalf("save multi-auth file: %v", errCall)
	}
	response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthSaveResponse](raw)
	if errDecode != nil {
		t.Fatalf("decode multi-auth save: %v", errDecode)
	}
	return response.Path
}
