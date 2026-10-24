package groupingapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestWritesRequireCanonicalIfMatch(t *testing.T) {
	requests := []struct{ method, path, body string }{
		{http.MethodPatch, "/activation", `{"enabled":true}`},
		{http.MethodPost, "/groups", `{"name":"Team"}`},
		{http.MethodPatch, "/groups/g1", `{"name":"Team"}`},
		{http.MethodDelete, "/groups/g1", ""},
		{http.MethodPatch, "/bindings", `{"token_ids":["t1"],"group_id":"all"}`},
		{http.MethodPost, "/bindings/rebind", `{"id":"c1","confirm":true}`},
	}
	for _, revision := range []string{"", "7", `W/"7"`, "*", `"7","8"`, `"0"`, `"-1"`, `"+7"`, `"07"`, `"7.0"`, `"18446744073709551616"`} {
		for _, request := range requests {
			t.Run(request.path+revision, func(t *testing.T) {
				backend := newBackend()
				result := perform(testRouter(backend), request.method, request.path, request.body, revision)
				if result.Code != http.StatusPreconditionFailed || backend.calls != 0 {
					t.Fatalf("status=%d calls=%d body=%s", result.Code, backend.calls, result.Body)
				}
			})
		}
	}
}

func TestMultipleIfMatchHeadersAreRejected(t *testing.T) {
	backend := newBackend()
	request := httptest.NewRequest(http.MethodPatch, "/v8/management/grouping/activation", strings.NewReader(`{"enabled":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("If-Match", `"7"`)
	request.Header.Add("If-Match", `"8"`)
	result := httptest.NewRecorder()
	testRouter(backend).ServeHTTP(result, request)
	if result.Code != http.StatusPreconditionFailed || backend.calls != 0 {
		t.Fatalf("status=%d calls=%d", result.Code, backend.calls)
	}
}

func TestStrictActivationBody(t *testing.T) {
	bodies := []string{
		"", `null`, `[]`, `true`, `{}`, `{"enabled":null}`, `{"enabled":"true"}`,
		`{"enabled":1}`, `{"enabled":true,"secret":"hidden"}`, `{"Enabled":true}`,
		`{"enabled":true,"enabled":false}`, `{"enabled":true,"\u0065nabled":false}`,
		`{"enabled":true} {}`, `{"enabled":true} garbage`, `{"enabled":`,
		`{"enabled":true,"confirm_permission_expansion":null}`,
		`{"enabled":true,"confirm_permission_expansion":"yes"}`,
		"{\"enabled\":true,\"x\":\"\xff\"}",
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			backend := newBackend()
			result := perform(testRouter(backend), http.MethodPatch, "/activation", body, `"7"`)
			if result.Code != http.StatusBadRequest || backend.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", result.Code, backend.calls, result.Body)
			}
		})
	}
}

func TestMalformedBodiesDoNotReachBackend(t *testing.T) {
	tests := []struct{ method, path, body string }{
		{http.MethodPost, "/initialize", `{"enabled":true}`},
		{http.MethodPost, "/initialize", ""},
		{http.MethodPost, "/groups", `{}`},
		{http.MethodPost, "/groups", `{"name":"  "}`},
		{http.MethodPost, "/groups", `{"name":null}`},
		{http.MethodPost, "/groups", `{"name":"line\nbreak"}`},
		{http.MethodPost, "/groups", fmt.Sprintf(`{"name":%q}`, strings.Repeat("文", 65))},
		{http.MethodPatch, "/groups/%20", `{"name":"Team"}`},
		{http.MethodDelete, "/groups/%20", ""},
		{http.MethodDelete, "/groups/g1", `{}`},
		{http.MethodPost, "/bindings/rebind", `{"id":"c1"}`},
		{http.MethodPost, "/bindings/rebind", `{"id":"c1","confirm":false}`},
		{http.MethodPost, "/bindings/rebind", `{"id":" c1","confirm":true}`},
	}
	for _, test := range tests {
		t.Run(test.path+test.body, func(t *testing.T) {
			backend := newBackend()
			result := perform(testRouter(backend), test.method, test.path, test.body, `"7"`)
			if result.Code != http.StatusBadRequest || backend.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", result.Code, backend.calls, result.Body)
			}
		})
	}
}

func TestInvalidBindingBatches(t *testing.T) {
	bodies := []string{
		`{"group_id":"all"}`, `{"token_ids":[],"group_id":"all"}`,
		`{"token_ids":["t1"]}`, `{"token_ids":["t1"],"group_id":" "}`,
		`{"token_ids":null,"group_id":"all"}`, `{"token_ids":[null],"group_id":"all"}`,
		`{"token_ids":["t1","t1"],"group_id":"all"}`,
		`{"token_ids":["id"],"credential_ids":["id"],"group_id":"all"}`,
		`{"token_ids":["t1",""],"group_id":"all"}`,
		`{"token_ids":["t1"," t2"],"group_id":"all"}`,
		`{"credential_ids":["a/b"],"group_id":"all"}`,
		`{"credential_ids":["a\\b"],"group_id":"all"}`,
		`{"credential_ids":["a\u0000b"],"group_id":"all"}`,
		fmt.Sprintf(`{"token_ids":[%q],"group_id":"all"}`, strings.Repeat("x", 129)),
		batchBody(t, 501),
	}
	for _, body := range bodies {
		for _, path := range []string{"/bindings", "/preview"} {
			t.Run(path+body, func(t *testing.T) {
				method := http.MethodPatch
				if path == "/preview" {
					method = http.MethodPost
				}
				backend := newBackend()
				result := perform(testRouter(backend), method, path, body, `"7"`)
				if result.Code != http.StatusBadRequest || backend.calls != 0 {
					t.Fatalf("status=%d calls=%d body=%s", result.Code, backend.calls, result.Body)
				}
			})
		}
	}
}

func batchBody(t *testing.T, size int) string {
	t.Helper()
	ids := make([]string, size)
	for index := range ids {
		ids[index] = fmt.Sprintf("id-%d", index)
	}
	body, err := json.Marshal(BindingRequest{TokenIDs: ids, GroupID: "all"})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestBodyTransportValidation(t *testing.T) {
	tests := []struct {
		contentType, body string
		status            int
	}{
		{"", `{}`, http.StatusUnsupportedMediaType},
		{"text/plain", `{}`, http.StatusUnsupportedMediaType},
		{"application/json;broken", `{}`, http.StatusUnsupportedMediaType},
		{"application/json", strings.Repeat(" ", maxBodyBytes+1), http.StatusRequestEntityTooLarge},
		{"application/json; charset=utf-8", `{}`, http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.contentType+fmt.Sprint(test.status), func(t *testing.T) {
			backend := newBackend()
			request := httptest.NewRequest(http.MethodPost, "/v8/management/grouping/initialize", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			result := httptest.NewRecorder()
			testRouter(backend).ServeHTTP(result, request)
			if result.Code != test.status || result.Code != http.StatusOK && backend.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", result.Code, backend.calls, result.Body)
			}
		})
	}
}

func TestConcurrentCASAllowsOnlyOneWrite(t *testing.T) {
	backend := newBackend()
	router := testRouter(backend)
	const count = 16
	results := make(chan int, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- perform(router, http.MethodPatch, "/activation", `{"enabled":true}`, `"7"`).Code
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for status := range results {
		if status == http.StatusOK {
			successes++
		} else if status != http.StatusPreconditionFailed {
			t.Fatalf("unexpected status: %d", status)
		}
	}
	if successes != 1 || backend.writes != 1 || backend.revision != 8 || backend.calls != count {
		t.Fatalf("CAS failed: successes=%d writes=%d revision=%d calls=%d", successes, backend.writes, backend.revision, backend.calls)
	}
}
