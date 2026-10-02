package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type groupingCallbackPolicy struct{ scope *groupingCallbackScope }

func (p groupingCallbackPolicy) BeginAttempt(ctx context.Context) (coreauth.CredentialAccessScope, error) {
	if _, ok := access.AuthenticatedPrincipalFromContext(ctx); !ok {
		return nil, errors.New("missing trusted identity")
	}
	return p.scope, nil
}

type groupingCallbackScope struct {
	allowed     map[string]bool
	uses        int
	revokeAfter int
}

func (s *groupingCallbackScope) Allows(a *coreauth.Auth) bool { return a != nil && s.allowed[a.ID] }
func (s *groupingCallbackScope) AuthorizeUse(_ context.Context, a *coreauth.Auth) error {
	s.uses++
	if !s.Allows(a) || (s.revokeAfter > 0 && s.uses >= s.revokeAfter) {
		return errors.New("permission revoked")
	}
	return nil
}

func groupingCallbackFixture(t *testing.T) (*Host, *coreauth.Auth, *groupingCallbackScope, string, context.Context) {
	t.Helper()
	host, a := newHostAuthRequestTestHost(t, &coreauth.Auth{ID: "allowed", Provider: "demo", ProxyURL: "direct", Attributes: map[string]string{"api_key": "fake-test-key", "runtime_only": "true"}})
	scope := &groupingCallbackScope{allowed: map[string]bool{"allowed": true}}
	host.currentAuthManager().SetCredentialAccessPolicy(groupingCallbackPolicy{scope: scope})
	ctx := access.WithAuthenticatedPrincipal(context.Background(), "config", "verified")
	id, cancel := host.openCallbackContextForPlugin(ctx, "plugin-a")
	t.Cleanup(cancel)
	return host, a, scope, id, withHostCallbackPluginID(context.Background(), "plugin-a")
}

func groupingCallbackRequest(t *testing.T, a *coreauth.Auth, callbackID, url string) []byte {
	t.Helper()
	raw, err := json.Marshal(pluginapi.HostAuthRequest{AuthIndex: a.Index, HostCallbackID: callbackID, URL: url, Headers: http.Header{"Authorization": {"Bearer $TOKEN$"}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGroupingHostAuthRequestRejectsBeforeTokenAndHTTP(t *testing.T) {
	host, a, scope, id, ctx := groupingCallbackFixture(t)
	scope.allowed[a.ID] = false
	_, err := host.callHostAuthRequest(ctx, groupingCallbackRequest(t, a, id, "http://upstream.invalid/"))
	if err == nil {
		t.Fatal("unpermitted credential sent")
	}
	var denied interface{ StatusCode() int }
	if !errors.As(err, &denied) || denied.StatusCode() != http.StatusForbidden {
		t.Fatalf("error=%v", err)
	}
}

func TestGroupingHostAuthRequestRechecksBeforeHTTP(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "allowed", true: "revoked"}[revoke], func(t *testing.T) {
			host, a, scope, id, ctx := groupingCallbackFixture(t)
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(http.StatusOK) }))
			defer server.Close()
			if revoke {
				scope.revokeAfter = 2
			}
			_, err := host.callHostAuthRequest(ctx, groupingCallbackRequest(t, a, id, server.URL))
			if revoke {
				if err == nil || hits.Load() != 0 {
					t.Fatalf("error=%v hits=%d", err, hits.Load())
				}
			} else if err != nil || hits.Load() != 1 {
				t.Fatalf("error=%v hits=%d", err, hits.Load())
			}
			wantUses := 4
			if revoke {
				wantUses = 2
			}
			if scope.uses != wantUses {
				t.Fatalf("authorizations=%d", scope.uses)
			}
		})
	}
}

func TestGroupingCallbackRequiresRegisteredOwner(t *testing.T) {
	host, _, _, id, caller := groupingCallbackFixture(t)
	for _, tc := range []struct {
		name, id string
		ctx      context.Context
	}{
		{"missing", "", caller}, {"guessed", "1", caller}, {"unknown", uuid.NewString(), caller},
		{"other-plugin", id, withHostCallbackPluginID(context.Background(), "plugin-b")},
		{"unidentified-plugin", id, context.Background()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := host.resolveGroupingCallbackContext(tc.ctx, tc.id); err == nil {
				t.Fatal("untrusted callback accepted")
			}
		})
	}
	if _, err := host.resolveGroupingCallbackContext(caller, id); err != nil {
		t.Fatal(err)
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.Version() != 4 {
		t.Fatalf("callback ID is not random UUID: %q", id)
	}
}
