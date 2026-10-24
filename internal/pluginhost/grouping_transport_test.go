package pluginhost

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type groupingRoundTripFunc func(*http.Request) (*http.Response, error)

func (f groupingRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestGroupingHTTPRedirectRechecksCredential(t *testing.T) {
	host, auth, scope, _, _ := groupingCallbackFixture(t)
	calls := 0
	client := (&hostHTTPClient{host: host, auth: auth}).withCredentialAccessTransport(&http.Client{
		Transport: groupingRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			scope.revokeAfter = scope.uses + 1
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://upstream.invalid/next"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		}),
	})
	ctx := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://upstream.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(req)
	if !coreauth.IsCredentialAccessError(err) || calls != 1 {
		t.Fatalf("redirect bypassed policy: calls=%d error=%v", calls, err)
	}
	var denied interface{ StatusCode() int }
	if !errors.As(err, &denied) || denied.StatusCode() != http.StatusForbidden {
		t.Fatalf("denial status lost: %v", err)
	}
}
