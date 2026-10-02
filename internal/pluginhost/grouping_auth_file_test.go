package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func TestGroupingAuthSaveRequiresSynchronousHostApplier(t *testing.T) {
	host, _, _, _, caller := groupingCallbackFixture(t)
	ctx := access.WithInternalOperation(context.Background(), access.InternalManagement)
	id, release := host.openCallbackContextForPlugin(ctx, "plugin-a")
	defer release()
	req, err := json.Marshal(map[string]any{"host_callback_id": id, "name": "fixture.json", "json": map[string]string{"type": "demo"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = host.callHostAuthSave(caller, req)
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) || status.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("unintegrated write error=%v", err)
	}
	calls := 0
	host.SetGroupingAuthFileApplier(func(ctx context.Context, name string, data []byte) (string, error) {
		calls++
		if _, trusted := access.InternalOperationFromContext(ctx); !trusted || name != "fixture.json" || !json.Valid(data) {
			t.Fatal("invalid write transaction input")
		}
		return "fixture.json", nil
	})
	if _, err = host.callHostAuthSave(caller, req); err != nil || calls != 1 {
		t.Fatalf("synchronous write calls=%d error=%v", calls, err)
	}
	host.SetGroupingAuthFileApplier(func(context.Context, string, []byte) (string, error) {
		return "", errors.New("transaction refused")
	})
	if _, err = host.callHostAuthSave(caller, req); err == nil {
		t.Fatal("failed host transaction fell back to direct disk write")
	}
}
