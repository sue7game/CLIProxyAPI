package groupingapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type modelPreviewBackend struct {
	*fakeBackend
	result PreviewResult
}

func (b *modelPreviewBackend) Preview(ctx context.Context, request BindingRequest) (PreviewResult, error) {
	_, err := b.fakeBackend.Preview(ctx, request)
	return b.result, err
}

func TestModelPreviewHTTPDistinguishesUnavailableFromEmpty(t *testing.T) {
	tests := []struct {
		available bool
		reason    string
		want      string
	}{
		{false, "", `"models_unavailable_reason":"not_configured","model_access_changes":null`},
		{false, "catalog_unavailable", `"models_unavailable_reason":"catalog_unavailable","model_access_changes":null`},
		{false, "private-secret", `"models_unavailable_reason":"not_configured","model_access_changes":null`},
		{true, "private-secret", `"models_scope":"registered_model_catalog","model_access_changes":[]`},
	}
	for _, test := range tests {
		backend := &modelPreviewBackend{fakeBackend: newBackend(), result: PreviewResult{
			Revision: 7, ModelsAvailable: test.available, ModelsUnavailableReason: test.reason}}
		response := perform(testRouter(backend), http.MethodPost, "/preview", `{"token_ids":["t1"],"group_id":"all"}`, "")
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.want) || strings.Contains(response.Body.String(), "private-secret") {
			t.Fatalf("incorrect model availability response: %d %s", response.Code, response.Body)
		}
	}
}

func TestModelPreviewHTTPKeepsExactDeltaFieldNames(t *testing.T) {
	backend := &modelPreviewBackend{fakeBackend: newBackend(), result: PreviewResult{Revision: 7, ModelsAvailable: true,
		ModelAccessChanges: []ModelAccessChange{{TokenID: "t1", Before: []string{}, After: []string{"model"},
			Added: []string{"model"}, Removed: []string{}}}}}
	response := perform(testRouter(backend), http.MethodPost, "/preview", `{"token_ids":["t1"],"group_id":"all"}`, "")
	var result map[string]json.RawMessage
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatalf("preview failed: %d %s", response.Code, response.Body)
	}
	want := `[{"token_id":"t1","before":[],"after":["model"],"added":["model"],"removed":[]}]`
	if string(result["model_access_changes"]) != want || string(result["models_available"]) != "true" {
		t.Fatalf("unexpected model schema: %s", response.Body)
	}
}
