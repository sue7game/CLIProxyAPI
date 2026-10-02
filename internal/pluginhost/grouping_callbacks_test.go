package pluginhost

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestGroupingModelCallbacksRequireOwnerAndPreservePrincipal(t *testing.T) {
	host, _, _, id, caller := groupingCallbackFixture(t)
	calls := 0
	check := func(ctx context.Context, req handlers.ModelExecutionRequest) {
		t.Helper()
		principal, ok := access.AuthenticatedPrincipalFromContext(ctx)
		if !ok || principal.Subject != "verified" {
			t.Fatal("trusted principal was not preserved")
		}
		if req.Path != "/v1/images/generations" {
			t.Fatalf("v8 model request path lost: %q", req.Path)
		}
		calls++
	}
	host.SetModelExecutor(&fakeHostModelExecutor{
		executeModel: func(ctx context.Context, req handlers.ModelExecutionRequest) (handlers.ModelExecutionResponse, *interfaces.ErrorMessage) {
			check(ctx, req)
			return handlers.ModelExecutionResponse{StatusCode: http.StatusOK}, nil
		},
		executeModelStream: func(ctx context.Context, req handlers.ModelExecutionRequest) (handlers.ModelExecutionStream, *interfaces.ErrorMessage) {
			check(ctx, req)
			chunks := make(chan handlers.ModelExecutionChunk)
			close(chunks)
			return handlers.ModelExecutionStream{StatusCode: http.StatusOK, Chunks: chunks}, nil
		},
	})
	for _, stream := range []bool{false, true} {
		method := pluginabi.MethodHostModelExecute
		if stream {
			method = pluginabi.MethodHostModelExecuteStream
		}
		req, err := json.Marshal(rpcHostModelExecutionRequest{HostCallbackID: id, HostModelExecutionRequest: pluginapi.HostModelExecutionRequest{Stream: stream, Path: "/v1/images/generations"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = host.callFromPlugin(withHostCallbackPluginID(context.Background(), "other"), method, req); err == nil {
			t.Fatal("another plugin borrowed the issuer")
		}
		if _, err = host.callFromPlugin(caller, method, req); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("model calls=%d", calls)
	}
}

func TestGroupingCredentialMutationRequiresTrustedOperation(t *testing.T) {
	host, auth, _, id, caller := groupingCallbackFixture(t)
	req, err := json.Marshal(map[string]any{"host_callback_id": id, "auth_index": auth.Index, "disabled": true, "name": "fixture.json", "json": map[string]string{"type": "demo"}, "internal_operation": "management"})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{pluginabi.MethodHostAuthSave, pluginabi.MethodHostAuthSetRuntimeOverride} {
		if _, err = host.callFromPlugin(caller, method, req); !coreauth.IsCredentialAccessError(err) {
			t.Fatalf("user mutation accepted: %s: %v", method, err)
		}
	}
	current, _ := host.currentAuthManager().GetByID(auth.ID)
	if current.EffectiveDisabled() {
		t.Fatal("untrusted runtime mutation was applied")
	}
	internal := access.WithInternalOperation(context.Background(), access.InternalManagement)
	id, closeCallback := host.openCallbackContextForPlugin(internal, "plugin-a")
	defer closeCallback()
	req, err = json.Marshal(map[string]string{"host_callback_id": id})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := host.authorizeGroupingMutation(caller, req)
	if _, trusted := access.InternalOperationFromContext(resolved); err != nil || !trusted {
		t.Fatalf("trusted operation lost: %v", err)
	}
}

func TestGroupingMissingManagerOrPolicyFailsClosed(t *testing.T) {
	host := New()
	host.runtimeConfig = &config.Config{Grouping: config.GroupingConfig{Enabled: true}}
	for _, manager := range []*coreauth.Manager{nil, coreauth.NewManager(nil, nil, nil)} {
		host.SetAuthManager(manager)
		if err := host.authorizeHostHTTP(context.Background(), nil); !coreauth.IsCredentialAccessError(err) {
			t.Fatalf("unconfigured HTTP access allowed: %v", err)
		}
		if _, err := host.callHostAuthList(context.Background(), []byte(`{}`)); !coreauth.IsCredentialAccessError(err) {
			t.Fatalf("unconfigured auth list allowed: %v", err)
		}
	}
}
