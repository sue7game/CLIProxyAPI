package groupingadmin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestHTTPAdapterWithRealBackendAndStore(t *testing.T) {
	f := newFixture(t, sourceRecord{"token", grouping.Token, "A", grouping.Active},
		sourceRecord{"credential", grouping.Credential, "B", grouping.Active})
	router := gin.New()
	groupingapi.Register(router.Group("/v0/management"), f.backend)
	binding := groupingapi.BindingRequest{TokenIDs: []string{f.ids["token"]}, GroupID: f.groups["B"]}
	result := requestBinding(t, router, binding, `"1"`)
	if result.Code != http.StatusConflict || snapshotOf(t, f).Revision != 1 {
		t.Fatalf("cross-group expansion bypassed consent: %d %s", result.Code, result.Body)
	}
	binding.ConfirmPermissionExpansion = true
	result = requestBinding(t, router, binding, `"1"`)
	if result.Code != http.StatusOK || result.Header().Get("ETag") != `"2"` ||
		strings.TrimSpace(result.Body.String()) != `{"applied_revision":2}` {
		t.Fatalf("confirmed write failed: %d %s", result.Code, result.Body)
	}
	result = requestBinding(t, router, binding, `"1"`)
	if result.Code != http.StatusPreconditionFailed || snapshotOf(t, f).Revision != 2 || f.notifications.Load() != 1 {
		t.Fatalf("stale write succeeded: %d %s", result.Code, result.Body)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	result = requestBinding(t, router, binding, `"2"`)
	if result.Code != http.StatusServiceUnavailable || f.notifications.Load() != 1 {
		t.Fatalf("closed store did not fail closed: %d %s", result.Code, result.Body)
	}
}

func requestBinding(t *testing.T, router http.Handler, binding groupingapi.BindingRequest, revision string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPatch, "/v0/management/grouping/bindings", strings.NewReader(string(data)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", revision)
	result := httptest.NewRecorder()
	router.ServeHTTP(result, request)
	return result
}

func TestCancellationNeverStartsAMutation(t *testing.T) {
	f := newFixture(t)
	before, data := snapshotOf(t, f), policyBytes(t, f)
	ctx, cancel := context.WithCancel(testContext())
	cancel()
	f.backend.options.Initialize = func(context.Context) (groupingapi.Status, error) {
		t.Error("canceled initialization reached callback")
		return groupingapi.Status{}, nil
	}
	f.backend.options.Activation = func(context.Context, uint64, groupingapi.Mutation) (groupingapi.ApplyResult, error) {
		t.Error("canceled activation reached callback")
		return groupingapi.ApplyResult{}, nil
	}
	if _, err := f.backend.Initialize(ctx); !errors.Is(err, groupingapi.ErrUnavailable) {
		t.Fatalf("canceled initialization accepted: %v", err)
	}
	for _, operation := range []groupingapi.Operation{groupingapi.CreateGroup, groupingapi.Activate, groupingapi.Rebind} {
		if _, err := f.backend.Apply(ctx, 1, groupingapi.Mutation{Operation: operation, Name: "new"}); !errors.Is(err, groupingapi.ErrUnavailable) {
			t.Fatalf("canceled mutation accepted: %v", err)
		}
	}
	if _, err := f.backend.Groups(nil); !errors.Is(err, groupingapi.ErrUnavailable) {
		t.Fatalf("missing request context accepted: %v", err)
	}
	assertUnchanged(t, f, before, data)
}

func TestOrdinaryStoreAccessUsesSharedMutex(t *testing.T) {
	f := newFixture(t)
	f.backend.options.Store = func() *grouping.Store {
		if f.mutex.TryLock() {
			f.mutex.Unlock()
			t.Error("store accessor ran without shared mutex")
		}
		return f.store
	}
	f.backend.options.Enabled = func() bool {
		if f.mutex.TryLock() {
			f.mutex.Unlock()
			t.Error("enabled accessor ran without shared mutex")
		}
		return false
	}
	f.backend.options.OnPolicyChanged = nil
	if _, err := f.backend.Status(testContext()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: "new"}); err != nil {
		t.Fatal(err)
	}
}
