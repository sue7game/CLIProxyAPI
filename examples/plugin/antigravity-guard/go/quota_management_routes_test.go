package main

import (
	"net/http"
	"testing"
)

func TestManagementQuotaRegistrationUsesDedicatedRefreshPath(t *testing.T) {
	const quotaPath = "/plugins/" + pluginID + "/quota"
	refreshRoutes := 0
	for _, route := range managementRoutes().Routes {
		if route.Path == quotaPath {
			t.Fatalf("plugin registered host-owned quota path: %s %s", route.Method, route.Path)
		}
		if route.Path == quotaPath+"/refresh" {
			refreshRoutes++
			if route.Method != http.MethodPost {
				t.Fatalf("refresh method = %q, want POST", route.Method)
			}
		}
	}
	if refreshRoutes != 1 {
		t.Fatalf("refresh route count = %d, want 1", refreshRoutes)
	}
}

func TestManagementQuotaRejectsHostPathAndReadOnlyRefresh(t *testing.T) {
	host := &fakeHost{}
	app := newApplication(host)
	defer app.shutdown()

	for _, request := range []managementRequest{
		{Method: http.MethodPost, Path: managementAPIPath + "/quota"},
		{Method: http.MethodGet, Path: managementAPIPath + "/quota/refresh"},
	} {
		request.Body = []byte(`{"auth_index":"ag-1"}`)
		response := app.dispatchManagement(request)
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s status = %d, want 404", request.Method, request.Path, response.StatusCode)
		}
	}
	if len(host.authRequests) != 0 {
		t.Fatal("unregistered quota routes must not invoke authenticated requests")
	}
}
