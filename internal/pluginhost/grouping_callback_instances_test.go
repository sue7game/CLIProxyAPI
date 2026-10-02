package pluginhost

import (
	"context"
	"encoding/json"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

func TestGroupingCallbackRejectsReloadedAndClosedInstances(t *testing.T) {
	host, id, caller, instance := groupingHTTPInstanceFixture(t)
	reloaded := withHostCallbackIdentity(context.Background(), "plugin-a", &hostCallbackInstance{})
	if _, errContext := host.resolveGroupingCallbackContext(reloaded, id); !coreauth.IsCredentialAccessError(errContext) {
		t.Fatalf("reloaded instance borrowed a stale callback: %v", errContext)
	}
	if _, errContext := host.resolveGroupingCallbackContext(caller, id); errContext != nil {
		t.Fatal(errContext)
	}
	instance.closed.Store(true)
	if _, errContext := host.resolveGroupingCallbackContext(caller, id); !coreauth.IsCredentialAccessError(errContext) {
		t.Fatalf("closed instance retained its callback: %v", errContext)
	}
}

func TestGroupingStreamOwnershipIncludesPluginInstance(t *testing.T) {
	for _, method := range []string{pluginabi.MethodHostModelStreamRead, pluginabi.MethodHostHTTPStreamRead, pluginabi.MethodHostStreamEmit} {
		t.Run(method, func(t *testing.T) {
			host, id, owner, _ := groupingHTTPInstanceFixture(t)
			streamID, closeMethod := openGroupingTestStream(t, host, id, method)
			raw, errMarshal := json.Marshal(map[string]string{"stream_id": streamID})
			if errMarshal != nil {
				t.Fatal(errMarshal)
			}
			other := withHostCallbackIdentity(context.Background(), "plugin-a", &hostCallbackInstance{})
			for _, operation := range []string{method, closeMethod} {
				if _, errCall := host.callFromPlugin(other, operation, raw); !coreauth.IsCredentialAccessError(errCall) {
					t.Fatalf("reloaded instance reached an old stream: %v", errCall)
				}
			}
			if errDenial := host.callbackAccessDenial(id).failure(nil); errDenial != nil {
				t.Fatalf("reloaded instance poisoned stream owner: %v", errDenial)
			}
			if _, errClose := host.callFromPlugin(owner, closeMethod, raw); errClose != nil {
				t.Fatal(errClose)
			}
		})
	}
}
