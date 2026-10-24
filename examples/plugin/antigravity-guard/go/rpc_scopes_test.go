package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

type scopeTestCall struct{ method, id string }
type scopeTestTransport struct {
	mu       sync.Mutex
	host     *fakeHost
	calls    []scopeTestCall
	rejectID string
}

func newScopeTestTransport() (*hostRPCClient, *scopeTestTransport) {
	transport := &scopeTestTransport{host: &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("scope-auth", 0)}, requestResponse: hostAuthResponse{StatusCode: http.StatusOK, Body: []byte("{}")}}}
	client := newHostRPCClient()
	client.transport = transport.call
	return client, transport
}

func (s *scopeTestTransport) call(method string, raw []byte) ([]byte, int, error) {
	var scope struct {
		ID string `json:"host_callback_id"`
	}
	if err := json.Unmarshal(raw, &scope); err != nil {
		return nil, 1, err
	}
	s.mu.Lock()
	s.calls = append(s.calls, scopeTestCall{method: method, id: scope.ID})
	reject := s.rejectID != "" && s.rejectID == scope.ID
	s.mu.Unlock()
	if reject {
		return nil, 1, fmt.Errorf("scope denied")
	}
	value, err := s.dispatch(method, raw)
	if err != nil {
		return nil, 1, err
	}
	response, err := okEnvelope(value)
	return response, 0, err
}

func (s *scopeTestTransport) dispatch(method string, raw []byte) (any, error) {
	switch method {
	case methodHostAuthList:
		files, err := s.host.ListAuths()
		return authListResponse{Files: files}, err
	case methodHostAuthSetRuntimeOverride:
		var request runtimeOverrideRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			return nil, err
		}
		return s.host.SetRuntimeOverride(request)
	case methodHostAuthRequest:
		var request hostAuthRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			return nil, err
		}
		return s.host.Request(request)
	default:
		return nil, fmt.Errorf("unsupported test callback %s", method)
	}
}

func (s *scopeTestTransport) takeCalls() []scopeTestCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	calls := append([]scopeTestCall(nil), s.calls...)
	s.calls = nil
	return calls
}

func assertScopeCalls(t *testing.T, calls []scopeTestCall, id string) {
	t.Helper()
	if len(calls) == 0 {
		t.Fatal("no host callback was exercised")
	}
	for _, call := range calls {
		if call.id != id {
			t.Fatalf("%s callback scope = %q, want %q", call.method, call.id, id)
		}
	}
}

func TestHostRPCScopesDoNotFallBackFromExplicitIdentity(t *testing.T) {
	client, transport := newScopeTestTransport()
	client.setMaintenanceCallback("maintenance")
	for _, id := range []string{"management", ""} {
		scoped := scopedHostClient(client, id)
		if _, err := scoped.ListAuths(); err != nil {
			t.Fatal(err)
		}
		if _, err := scoped.SetRuntimeOverride(runtimeOverrideRequest{AuthIndex: "scope-auth"}); err != nil {
			t.Fatal(err)
		}
		if _, err := scoped.Request(hostAuthRequest{AuthIndex: "scope-auth", HostCallbackID: "maintenance"}); err != nil {
			t.Fatal(err)
		}
		assertScopeCalls(t, transport.takeCalls(), id)
	}
	if _, err := client.ListAuths(); err != nil {
		t.Fatal(err)
	}
	assertScopeCalls(t, transport.takeCalls(), "maintenance")
	if _, err := client.Request(hostAuthRequest{HostCallbackID: "explicit"}); err != nil {
		t.Fatal(err)
	}
	assertScopeCalls(t, transport.takeCalls(), "explicit")
	transport.rejectID = "expired"
	if _, err := scopedHostClient(client, "expired").ListAuths(); err == nil {
		t.Fatal("expired callback accepted")
	}
	calls := transport.takeCalls()
	if len(calls) != 1 {
		t.Fatal("denied callback retried with another identity")
	}
	assertScopeCalls(t, calls, "expired")
}

func configureScopeTest(t *testing.T, app *application, enabled bool, shortID, maintenanceID string) {
	t.Helper()
	raw, err := json.Marshal(lifecycleRequest{ConfigYAML: []byte(fmt.Sprintf("enabled: %t\n", enabled)), HostCallbackID: shortID, MaintenanceCallbackID: maintenanceID})
	if err != nil {
		t.Fatal(err)
	}
	if err = app.configure(raw); err != nil {
		t.Fatal(err)
	}
}

func TestGuardLifecycleCleanupUsesShortScopeAndRollbackReplacesMaintenance(t *testing.T) {
	client, transport := newScopeTestTransport()
	app := newApplication(client)
	t.Cleanup(app.shutdown)
	configureScopeTest(t, app, true, "register", "maintenance-old")
	app.guard.applyCooldown("scope-auth", actionDisable, 0, "test", "test", time.Now().Add(time.Hour))
	assertScopeCalls(t, transport.takeCalls(), "maintenance-old")
	configureScopeTest(t, app, false, "cleanup", "")
	assertScopeCalls(t, transport.takeCalls(), "cleanup")
	if id := client.hostCallbackID(); id != "" {
		t.Fatalf("disabled plugin retained %q", id)
	}
	configureScopeTest(t, app, true, "rollback", "maintenance-new")
	app.guard.applyCooldown("scope-auth", actionDisable, 0, "test", "test", time.Now().Add(time.Hour))
	assertScopeCalls(t, transport.takeCalls(), "maintenance-new")
}

func TestGuardManagementCallbacksAlwaysUseRequestScope(t *testing.T) {
	client, transport := newScopeTestTransport()
	app := newApplication(client)
	t.Cleanup(app.shutdown)
	configureScopeTest(t, app, true, "register", "maintenance")
	requests := []managementRequest{
		{Method: http.MethodGet, Path: managementAPIPath + "/state"},
		{Method: http.MethodPost, Path: managementAPIPath + "/quota/refresh", Body: []byte(`{"auth_index":"scope-auth"}`)},
		{Method: http.MethodPost, Path: managementAPIPath + "/proxy", Body: []byte(`{"auth_index":"scope-auth","mode":"direct"}`)},
		{Method: http.MethodPost, Path: managementAPIPath + "/recover", Body: []byte(`{"auth_index":"scope-auth"}`)},
		{Method: http.MethodPost, Path: managementAPIPath + "/cooldown/clear", Body: []byte(`{"auth_index":"scope-auth"}`)},
		{Method: http.MethodPost, Path: managementAPIPath + "/settings", Body: []byte(`{"auto_429_enabled":false,"action":"disable","temporary_priority":0}`)},
		{Method: http.MethodPost, Path: managementAPIPath + "/proxy/alias", Body: []byte(`{"proxy_id":"missing","alias":"test"}`)},
	}
	for _, request := range requests {
		request.HostCallbackID = "management"
		app.dispatchManagement(request)
		assertScopeCalls(t, transport.takeCalls(), "management")
	}
	app.dispatchManagement(managementRequest{Method: http.MethodGet, Path: managementAPIPath + "/state"})
	assertScopeCalls(t, transport.takeCalls(), "")
}

func TestGuardConcurrentManagementScopeDoesNotLeakIntoBackground(t *testing.T) {
	client, transport := newScopeTestTransport()
	app := newApplication(client)
	t.Cleanup(app.shutdown)
	configureScopeTest(t, app, true, "register", "maintenance")
	app.guard.applyCooldown("scope-auth", actionDisable, 0, "test", "test", time.Now().Add(time.Hour))
	transport.takeCalls()
	var workers sync.WaitGroup
	for range 20 {
		workers.Add(2)
		go func() { defer workers.Done(); app.stateResponse("management") }()
		go func() { defer workers.Done(); app.guard.reconcileConfiguredDisables(time.Now()) }()
	}
	workers.Wait()
	for _, call := range transport.takeCalls() {
		if call.id != "management" && call.id != "maintenance" {
			t.Fatalf("unexpected scope %q", call.id)
		}
	}
}
