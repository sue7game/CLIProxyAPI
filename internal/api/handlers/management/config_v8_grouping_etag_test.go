package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigV8GroupingPreservesUpstreamIfMatchSemantics(t *testing.T) {
	f := newV8GroupingFixture(t, v8GroupingDocument)
	for _, headers := range [][]string{{"*"}, {`"stale"`, f.etag(t)}, {""}, {`W/` + f.etag(t)}} {
		request := httptest.NewRequest(http.MethodPut, "/v8/management/config/server/port", strings.NewReader("8318"))
		for _, value := range headers {
			request.Header.Add("If-Match", value)
		}
		if len(headers) > 1 {
			request.Header["If-Match"][1] = f.etag(t)
		}
		response := httptest.NewRecorder()
		f.router.ServeHTTP(response, request)
		want := http.StatusOK
		if headers[0] == "" || strings.HasPrefix(headers[0], "W/") {
			want = http.StatusPreconditionFailed
		}
		if response.Code != want || response.Header().Get("ETag") != f.etag(t) {
			t.Fatalf("If-Match %q: status=%d ETag=%s body=%s", headers, response.Code, response.Header().Get("ETag"), response.Body.String())
		}
	}
}

func TestConfigV8GroupingIdentityRemovalRejectsWildcard(t *testing.T) {
	f := newV8GroupingFixture(t, v8GroupingDocument)
	response := f.request(http.MethodDelete, "/v8/management/config/access/api-keys", "", "*")
	if response.Code != http.StatusPreconditionFailed || len(f.calls) != 0 {
		t.Fatalf("wildcard authorized identity removal: %d %s", response.Code, response.Body.String())
	}
	response = f.request(http.MethodDelete, "/v8/management/config/access/api-keys", "", `"stale", `+f.etag(t))
	if response.Code != http.StatusOK || len(f.calls) != 1 {
		t.Fatalf("matching strong tag list was rejected: %d %s", response.Code, response.Body.String())
	}
}
