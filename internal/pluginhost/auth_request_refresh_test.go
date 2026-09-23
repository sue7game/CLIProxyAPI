package pluginhost

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestHostAuthRequestRefreshesExpiredAntigravityToken(t *testing.T) {
	const (
		oldToken        = "old-access-token"
		staleCamelToken = "stale-camel-access-token"
		newToken        = "new-access-token"
	)
	executor := &hostAuthRefreshExecutor{newToken: newToken}
	requestContext := context.WithValue(context.Background(), "cliproxy.roundtripper", hostAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Authorization"); got != "Bearer "+newToken {
			t.Errorf("Authorization = %q, want refreshed token", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"groups":[]}`)),
			Request:    req,
		}, nil
	}))

	host, auth := newHostAuthRequestTestHost(t, &coreauth.Auth{
		ID:       "antigravity-refresh",
		Provider: "antigravity",
		Metadata: map[string]any{
			"accessToken":   staleCamelToken,
			"access_token":  oldToken,
			"refresh_token": "refresh-token-for-test",
			"expired":       time.Now().Add(-time.Minute).Format(time.RFC3339),
		},
		Attributes: map[string]string{"runtime_only": "true"},
	})
	host.currentAuthManager().RegisterExecutor(executor)
	rawRequest, errMarshal := json.Marshal(pluginapi.HostAuthRequest{
		AuthIndex: auth.Index,
		Method:    http.MethodPost,
		URL:       "https://quota.example.test/v1internal:fetchAvailableModels",
		Headers: http.Header{
			"Authorization": {"Bearer $TOKEN$"},
			"Content-Type":  {"application/json"},
		},
		Body: []byte(`{}`),
	})
	if errMarshal != nil {
		t.Fatalf("Marshal() error = %v", errMarshal)
	}

	rawResponse, errCall := host.callFromPlugin(requestContext, pluginabi.MethodHostAuthRequest, rawRequest)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	response, errDecode := decodeRPCEnvelope[pluginapi.HostAuthRequestResponse](rawResponse)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if response.StatusCode != http.StatusOK || string(response.Body) != `{"groups":[]}` {
		t.Fatalf("response = %#v, want quota response", response)
	}
	if got := executor.refreshCalls.Load(); got != 1 {
		t.Fatalf("Refresh() calls = %d, want 1", got)
	}
	current, ok := host.currentAuthManager().GetByID(auth.ID)
	if !ok {
		t.Fatal("refreshed auth disappeared")
	}
	if got := hostAntigravityTokenValue(current); got != newToken {
		t.Fatalf("saved access token = %q, want refreshed token", got)
	}
	if got := current.Metadata["accessToken"]; got != staleCamelToken {
		t.Fatalf("stale camel-case token = %#v, want test fixture preserved", got)
	}
	if current.LastRefreshedAt.IsZero() {
		t.Fatal("LastRefreshedAt was not updated")
	}
	if got := current.Metadata["executor_refresh_metadata"]; got != "preserved" {
		t.Fatalf("executor refresh metadata = %#v, want preserved", got)
	}
	if got := current.Metadata["refresh_token"]; got != "refresh-token-for-test" {
		t.Fatalf("refresh token metadata = %#v, want original value preserved", got)
	}
}

func TestHostAuthRequestConcurrentExpiredTokenRefreshesOnce(t *testing.T) {
	const (
		oldToken = "shared-old-access-token"
		newToken = "shared-new-access-token"
	)
	executor := &hostAuthRefreshExecutor{
		newToken:       newToken,
		refreshStarted: make(chan struct{}),
		refreshRelease: make(chan struct{}),
	}
	defer func() {
		select {
		case <-executor.refreshRelease:
		default:
			close(executor.refreshRelease)
		}
	}()
	host, staleAuth := newHostAuthRequestTestHost(t, &coreauth.Auth{
		ID:       "antigravity-concurrent-refresh",
		Provider: "antigravity",
		Metadata: map[string]any{
			"access_token":  oldToken,
			"refresh_token": "shared-refresh-token",
			"expired":       time.Now().Add(-time.Minute).Format(time.RFC3339),
		},
		Attributes: map[string]string{"runtime_only": "true"},
	})
	host.currentAuthManager().RegisterExecutor(executor)

	type refreshResult struct {
		token string
		auth  *coreauth.Auth
		err   error
	}
	resolve := func(results chan<- refreshResult) {
		token, updated, errResolve := host.resolveHostAntigravityToken(context.Background(), staleAuth)
		results <- refreshResult{token: token, auth: updated, err: errResolve}
	}
	firstResult := make(chan refreshResult, 1)
	go resolve(firstResult)
	select {
	case <-executor.refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("first refresh did not start")
	}

	secondStarted := make(chan struct{})
	secondResult := make(chan refreshResult, 1)
	go func() {
		close(secondStarted)
		resolve(secondResult)
	}()
	<-secondStarted
	select {
	case result := <-secondResult:
		t.Fatalf("second request completed before first refresh was released: %#v", result)
	case <-time.After(250 * time.Millisecond):
	}
	if got := executor.refreshCalls.Load(); got != 1 {
		t.Fatalf("Refresh() calls while first refresh is blocked = %d, want 1", got)
	}
	close(executor.refreshRelease)

	for _, resultChannel := range []<-chan refreshResult{firstResult, secondResult} {
		var result refreshResult
		select {
		case result = <-resultChannel:
		case <-time.After(time.Second):
			t.Fatal("refresh request did not complete after release")
		}
		if result.err != nil {
			t.Fatalf("resolveHostAntigravityToken() error = %v", result.err)
		}
		if result.token != newToken {
			t.Fatalf("resolved token = %q, want %q", result.token, newToken)
		}
		if result.auth == nil || hostAntigravityTokenValue(result.auth) != newToken {
			t.Fatalf("resolved auth = %#v, want refreshed auth", result.auth)
		}
	}
	if got := executor.refreshCalls.Load(); got != 1 {
		t.Fatalf("Refresh() calls = %d, want 1", got)
	}
	current, ok := host.currentAuthManager().GetByID(staleAuth.ID)
	if !ok || current == nil {
		t.Fatal("refreshed auth disappeared")
	}
	if got := current.Metadata["executor_refresh_metadata"]; got != "preserved" {
		t.Fatalf("executor refresh metadata = %#v, want preserved", got)
	}
}

type hostAuthRefreshExecutor struct {
	newToken       string
	refreshCalls   atomic.Int32
	refreshStarted chan struct{}
	refreshRelease chan struct{}
}

func (e *hostAuthRefreshExecutor) Identifier() string {
	return "antigravity"
}

func (e *hostAuthRefreshExecutor) Execute(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, nil
}

func (e *hostAuthRefreshExecutor) ExecuteStream(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	return nil, nil
}

func (e *hostAuthRefreshExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	call := e.refreshCalls.Add(1)
	if call == 1 && e.refreshStarted != nil {
		close(e.refreshStarted)
		if e.refreshRelease != nil {
			<-e.refreshRelease
		}
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = e.newToken
	auth.Metadata["expired"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	auth.Metadata["executor_refresh_metadata"] = "preserved"
	return auth, nil
}

func (e *hostAuthRefreshExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, nil
}

func (e *hostAuthRefreshExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

type hostAuthRoundTripFunc func(*http.Request) (*http.Response, error)

func (f hostAuthRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
