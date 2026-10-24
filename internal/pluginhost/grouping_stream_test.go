package pluginhost

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func openGroupingTestStream(t *testing.T, host *Host, callbackID, method string) (string, string) {
	t.Helper()
	switch method {
	case pluginabi.MethodHostModelStreamRead:
		chunks := make(chan handlers.ModelExecutionChunk, 1)
		chunks <- handlers.ModelExecutionChunk{Payload: []byte("model")}
		return host.modelStreams.open(callbackID, chunks, nil), pluginabi.MethodHostModelStreamClose
	case pluginabi.MethodHostHTTPStreamRead:
		chunks := make(chan pluginapi.HTTPStreamChunk, 1)
		chunks <- pluginapi.HTTPStreamChunk{Payload: []byte("http")}
		_, pluginID, instance, _ := host.lookupCallbackContext(callbackID)
		return host.httpStreams.openOwned(pluginID, instance, chunks, nil, nil, callbackID), pluginabi.MethodHostHTTPStreamClose
	default:
		id, _, cleanup := host.streams.openOwned(context.Background(), callbackID)
		t.Cleanup(cleanup)
		return id, pluginabi.MethodHostStreamClose
	}
}

func TestGroupingStreamsRequireOwnerForDataAndClose(t *testing.T) {
	for _, method := range []string{pluginabi.MethodHostModelStreamRead, pluginabi.MethodHostHTTPStreamRead, pluginabi.MethodHostStreamEmit} {
		t.Run(method, func(t *testing.T) {
			host, _, _, id, caller := groupingCallbackFixture(t)
			streamID, closeMethod := openGroupingTestStream(t, host, id, method)
			parsed, err := uuid.Parse(streamID)
			if err != nil || parsed.Version() != 4 {
				t.Fatalf("stream ID is not random: %q", streamID)
			}
			req, err := json.Marshal(map[string]string{"stream_id": streamID})
			if err != nil {
				t.Fatal(err)
			}
			other := withHostCallbackPluginID(context.Background(), "other")
			for _, operation := range []string{method, closeMethod} {
				if _, err := host.callFromPlugin(other, operation, req); err == nil {
					t.Fatalf("foreign stream access accepted: %s", operation)
				}
			}
			if err := host.authorizeGroupedStream(caller, method, streamID); err != nil {
				t.Fatal(err)
			}
			if _, err := host.callFromPlugin(caller, closeMethod, req); err != nil {
				t.Fatal(err)
			}
			if err := host.authorizeGroupedStream(caller, method, "1"); err == nil {
				t.Fatal("guessed stream accepted")
			}
			if err := host.callbackAccessDenial(id).failure(nil); err != nil {
				t.Fatalf("foreign callback poisoned owner: %v", err)
			}
		})
	}
}

func TestGroupingStreamsRejectExpiredCallbackOwner(t *testing.T) {
	host, _, _, _, caller := groupingCallbackFixture(t)
	id, release := host.openCallbackContextForPlugin(context.Background(), "plugin-a")
	streamID, _ := openGroupingTestStream(t, host, id, pluginabi.MethodHostHTTPStreamRead)
	defer host.httpStreams.close("plugin-a", nil, streamID)
	release()
	if err := host.authorizeGroupedStream(caller, pluginabi.MethodHostHTTPStreamRead, streamID); err == nil {
		t.Fatal("expired scope still owns stream")
	}
	host.currentAuthManager().SetCredentialAccessPolicy(nil)
	if err := host.authorizeGroupedStream(context.Background(), pluginabi.MethodHostHTTPStreamRead, streamID); err != nil {
		t.Fatalf("disabled grouping changed legacy stream behavior: %v", err)
	}
}
