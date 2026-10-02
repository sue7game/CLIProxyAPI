package pluginhost

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestGroupingAuthListAndRuntimeFilterCredentials(t *testing.T) {
	host, allowed, _, id, caller := groupingCallbackFixture(t)
	blocked, err := host.currentAuthManager().Register(context.Background(), &coreauth.Auth{ID: "blocked", Provider: "demo", Attributes: map[string]string{"runtime_only": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(map[string]string{"host_callback_id": id})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := host.callHostAuthList(caller, request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := decodeRPCEnvelope[rpcHostAuthListResponse](raw)
	if err != nil || len(response.Files) != 1 || response.Files[0].AuthIndex != allowed.Index {
		t.Fatalf("response=%v error=%v", response, err)
	}
	for _, a := range []*coreauth.Auth{allowed, blocked} {
		rawRequest := groupingCallbackRequest(t, a, id, "http://unused.invalid/")
		_, err := host.callHostAuthGetRuntime(caller, rawRequest)
		if (a.ID == "allowed") != (err == nil) {
			t.Fatalf("id=%s error=%v", a.ID, err)
		}
	}
}

func TestGroupingAuthCallbacksRejectMissingIdentity(t *testing.T) {
	host, a, _, _, caller := groupingCallbackFixture(t)
	id, cancel := host.openCallbackContextForPlugin(context.Background(), "plugin-a")
	defer cancel()
	request := groupingCallbackRequest(t, a, id, "http://unused.invalid/")
	for _, method := range []string{pluginabi.MethodHostAuthList, pluginabi.MethodHostAuthGet, pluginabi.MethodHostAuthGetRuntime, pluginabi.MethodHostAuthRequest} {
		if _, err := host.callFromPlugin(caller, method, request); err == nil {
			t.Fatalf("anonymous callback allowed: %s", method)
		}
	}
}

func groupingFileFixture(t *testing.T) (*Host, *coreauth.Auth, string, context.Context) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.json")
	metadata := map[string]any{"type": "demo", "api_key": "fixture-secret"}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	host, a := newHostAuthRequestTestHost(t, &coreauth.Auth{ID: "allowed", Provider: "demo", FileName: "credential.json", Metadata: metadata, Attributes: map[string]string{"path": path, "runtime_only": "true"}})
	host.currentAuthManager().SetCredentialAccessPolicy(groupingCallbackPolicy{scope: &groupingCallbackScope{allowed: map[string]bool{a.ID: true}}})
	ctx := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
	id, cancel := host.openCallbackContextForPlugin(ctx, "plugin-a")
	t.Cleanup(cancel)
	return host, a, id, withHostCallbackPluginID(context.Background(), "plugin-a")
}

func TestGroupingRawCredentialRejectsSharedAndReplacedSources(t *testing.T) {
	for _, variant := range []string{"single", "shared-path", "hardlink", "virtual", "replaced"} {
		t.Run(variant, func(t *testing.T) {
			host, a, id, caller := groupingFileFixture(t)
			prepareGroupingFileVariant(t, host, a, variant)
			raw, err := host.callHostAuthGet(caller, groupingCallbackRequest(t, a, id, "http://unused.invalid/"))
			if variant == "single" {
				if err != nil {
					t.Fatal(err)
				}
				response, err := decodeRPCEnvelope[rpcHostAuthGetResponse](raw)
				if err != nil || !json.Valid(response.JSON) {
					t.Fatalf("invalid JSON response: %v", err)
				}
			} else if err == nil {
				t.Fatal("shared or changed source exposed")
			}
		})
	}
}

func prepareGroupingFileVariant(t *testing.T, host *Host, a *coreauth.Auth, variant string) {
	t.Helper()
	path := a.Attributes["path"]
	switch variant {
	case "shared-path", "hardlink":
		if variant == "hardlink" {
			other := filepath.Join(filepath.Dir(path), "other.json")
			if err := os.Link(path, other); err != nil {
				t.Fatal(err)
			}
			path = other
		}
		_, err := host.currentAuthManager().Register(context.Background(), &coreauth.Auth{ID: "blocked", Provider: "demo", Attributes: map[string]string{"path": path, "runtime_only": "true"}})
		if err != nil {
			t.Fatal(err)
		}
	case "virtual":
		coreauth.MarkPluginVirtualAuth(a, path, 0)
		if _, err := host.currentAuthManager().Update(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	case "replaced":
		if err := os.WriteFile(path, []byte(`{"type":"demo","api_key":"other-secret"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGroupingRawCredentialDoesNotReadBlockedSource(t *testing.T) {
	host, a, scope, id, caller := groupingCallbackFixture(t)
	scope.allowed[a.ID] = false
	a.Attributes["path"] = filepath.Join(t.TempDir(), "nonexistent.json")
	if _, err := host.currentAuthManager().Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	_, err := host.callHostAuthGet(caller, groupingCallbackRequest(t, a, id, "http://unused.invalid/"))
	if err == nil || os.IsNotExist(err) {
		t.Fatalf("read attempted before authorization: %v", err)
	}
}

var _ = pluginapi.HostAuthFileEntry{}
