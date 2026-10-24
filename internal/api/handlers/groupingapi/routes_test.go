package groupingapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestReadRoutes(t *testing.T) {
	for _, path := range []string{"/status", "/groups", "/tokens", "/credentials"} {
		t.Run(path, func(t *testing.T) {
			backend := newBackend()
			result := perform(testRouter(backend), http.MethodGet, path, "", "")
			if result.Code != http.StatusOK || result.Header().Get("ETag") != `"7"` {
				t.Fatalf("status=%d headers=%v body=%s", result.Code, result.Header(), result.Body)
			}
			if result.Header().Get("Cache-Control") != "no-store" || backend.writes != 0 {
				t.Fatal("read must be uncached and must not write")
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(result.Body.Bytes(), &body); err != nil || string(body["revision"]) != "7" {
				t.Fatalf("invalid response: %s", result.Body)
			}
			if path == "/tokens" && backend.lastKind != KindToken || path == "/credentials" && backend.lastKind != KindCredential {
				t.Fatalf("wrong identity kind: %s", backend.lastKind)
			}
			if path == "/tokens" || path == "/credentials" {
				if string(body["items"]) != "[]" {
					t.Fatal("empty items must be an array")
				}
			}
		})
	}
}

func TestInitializeDoesNotActivate(t *testing.T) {
	backend := newBackend()
	result := perform(testRouter(backend), http.MethodPost, "/initialize", `{}`, "")
	if result.Code != http.StatusOK || backend.enabled || !backend.initialized || backend.writes != 1 {
		t.Fatalf("initialization failed: status=%d body=%s", result.Code, result.Body)
	}
	var body struct {
		Status
		AppliedRevision uint64 `json:"applied_revision"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &body); err != nil || body.Enabled || body.AppliedRevision != 7 {
		t.Fatalf("invalid initialization result: %s", result.Body)
	}
}

func TestMutationRoutes(t *testing.T) {
	tests := []struct {
		method, path, body string
		command            Mutation
	}{
		{http.MethodPatch, "/activation", `{"enabled":true}`, Mutation{Operation: Activate, Enabled: true}},
		{http.MethodPatch, "/activation", `{"enabled":false,"confirm_permission_expansion":true}`,
			Mutation{Operation: Activate, ConfirmPermissionExpansion: true}},
		{http.MethodPost, "/groups", `{"name":"  Team A  "}`, Mutation{Operation: CreateGroup, Name: "Team A"}},
		{http.MethodPatch, "/groups/group-a", `{"name":"Team B"}`, Mutation{Operation: RenameGroup, ID: "group-a", Name: "Team B"}},
		{http.MethodDelete, "/groups/group-a", "", Mutation{Operation: DeleteGroup, ID: "group-a"}},
		{http.MethodPatch, "/bindings", `{"token_ids":["t1"],"credential_ids":["c1"],"group_id":"all","confirm_permission_expansion":true}`,
			Mutation{Operation: Bind, Binding: BindingRequest{TokenIDs: []string{"t1"}, CredentialIDs: []string{"c1"}, GroupID: "all", ConfirmPermissionExpansion: true}}},
		{http.MethodPost, "/bindings/rebind", `{"id":"c1","confirm":true}`, Mutation{Operation: Rebind, ID: "c1", Confirm: true}},
	}
	for _, test := range tests {
		t.Run(test.method+test.path+test.body, func(t *testing.T) {
			backend := newBackend()
			result := perform(testRouter(backend), test.method, test.path, test.body, `"7"`)
			if result.Code != http.StatusOK || backend.writes != 1 || !reflect.DeepEqual(backend.lastCommand, test.command) {
				t.Fatalf("status=%d body=%s command=%+v", result.Code, result.Body, backend.lastCommand)
			}
			if strings.TrimSpace(result.Body.String()) != `{"applied_revision":8}` || result.Header().Get("ETag") != `"8"` {
				t.Fatalf("incorrect write response: %s", result.Body)
			}
		})
	}
}

func TestPreviewIsReadOnlyAndRevisioned(t *testing.T) {
	backend := newBackend()
	result := perform(testRouter(backend), http.MethodPost, "/preview",
		`{"token_ids":["t1"],"credential_ids":["c1"],"group_id":"group-a"}`, "")
	if result.Code != http.StatusOK || backend.calls != 1 || backend.writes != 0 {
		t.Fatalf("preview failed: status=%d body=%s", result.Code, result.Body)
	}
	if backend.lastPreview.GroupID != "group-a" || strings.TrimSpace(result.Body.String()) != `{"revision":7,"affected_count":2,"permission_expansion":false,"credential_access_changes":[],"models_available":false,"models_scope":"registered_model_catalog","models_unavailable_reason":"not_configured","model_access_changes":null}` {
		t.Fatalf("incorrect preview: %s", result.Body)
	}
}

func TestBackendErrorsAreMappedAndRedacted(t *testing.T) {
	tests := []struct {
		err  error
		code int
	}{
		{fmt.Errorf("private-secret: %w", ErrConflict), http.StatusConflict},
		{fmt.Errorf("private-secret: %w", ErrPrecondition), http.StatusPreconditionFailed},
		{fmt.Errorf("private-secret: %w", ErrUnavailable), http.StatusServiceUnavailable},
		{errors.New("private-secret"), http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		for _, path := range []string{"/status", "/groups", "/tokens", "/credentials", "/initialize", "/preview", "/activation"} {
			t.Run(fmt.Sprintf("%d%s", test.code, path), func(t *testing.T) {
				backend := newBackend()
				backend.err = test.err
				method, body := errorRequest(path)
				result := perform(testRouter(backend), method, path, body, `"7"`)
				if result.Code != test.code || backend.writes != 0 || backend.revision != 7 {
					t.Fatalf("status=%d body=%s writes=%d", result.Code, result.Body, backend.writes)
				}
				if strings.Contains(result.Body.String(), "private-secret") || strings.Contains(result.Body.String(), "applied_revision") {
					t.Fatal("failure leaked backend details or claimed an applied revision")
				}
			})
		}
	}
}

func errorRequest(path string) (string, string) {
	switch path {
	case "/activation":
		return http.MethodPatch, `{"enabled":true}`
	case "/initialize":
		return http.MethodPost, `{}`
	case "/preview":
		return http.MethodPost, `{"token_ids":["t1"],"group_id":"all"}`
	default:
		return http.MethodGet, ""
	}
}

func TestManagementAuthenticationIsInherited(t *testing.T) {
	backend := newBackend()
	router := testRouter(backend, func(c *gin.Context) { c.AbortWithStatus(http.StatusUnauthorized) })
	for _, route := range router.Routes() {
		result := perform(router, route.Method, strings.TrimPrefix(route.Path, "/v8/management/grouping"), `{}`, `"7"`)
		if result.Code != http.StatusUnauthorized {
			t.Fatalf("route bypassed authentication: %s %s", route.Method, route.Path)
		}
	}
	if backend.calls != 0 {
		t.Fatal("unauthenticated request reached backend")
	}
}

func TestMissingBackendFailsClosed(t *testing.T) {
	result := perform(testRouter(nil), http.MethodPatch, "/activation", `{"enabled":true}`, `"7"`)
	if result.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status: %d", result.Code)
	}
}

func TestRequestContextReachesBackend(t *testing.T) {
	backend := newBackend()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/v8/management/grouping/status", nil).WithContext(ctx)
	testRouter(backend).ServeHTTP(httptest.NewRecorder(), request)
	if backend.lastContext != ctx || backend.lastContext.Err() != context.Canceled {
		t.Fatal("request cancellation was lost")
	}
}
