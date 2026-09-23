package helps

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestNewProxyAwareHTTPClientDirectBypassesGlobalProxy(t *testing.T) {
	t.Parallel()

	client := NewProxyAwareHTTPClient(
		context.Background(),
		&config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"}},
		&cliproxyauth.Auth{ProxyURL: "direct"},
		0,
	)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("expected direct transport to disable proxy function")
	}
}

func TestNewDevinHTTPClient_ReusesTransportFromContext(t *testing.T) {
	baseTransport := &http.Transport{}
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", baseTransport)

	c1 := NewDevinHTTPClient(ctx, nil, nil, 0)
	c2 := NewDevinHTTPClient(ctx, nil, nil, 0)

	if c1.Transport != c2.Transport {
		t.Errorf("expected c1.Transport == c2.Transport across requests, got different pointers %p vs %p", c1.Transport, c2.Transport)
	}

	tr, ok := c1.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", c1.Transport)
	}
	if !tr.DisableCompression {
		t.Error("expected DisableCompression = true")
	}
}

func TestNewDevinHTTPClient_NonStandardRoundTripperDisablesGzip(t *testing.T) {
	var seenEncoding string
	customRT := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		seenEncoding = req.Header.Get("Accept-Encoding")
		return &http.Response{StatusCode: 200}, nil
	})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", customRT)

	c := NewDevinHTTPClient(ctx, nil, nil, 0)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.invalid", nil)
	_, _ = c.Transport.RoundTrip(req)

	if seenEncoding != "identity" {
		t.Errorf("expected Accept-Encoding: identity, got %q", seenEncoding)
	}
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewProxyAwareHTTPClientUsesRuntimeProxyOverride(t *testing.T) {
	t.Parallel()

	manager := cliproxyauth.NewManager(nil, nil, nil)
	auth := &cliproxyauth.Auth{
		ID:       "antigravity-runtime-proxy",
		Provider: "antigravity",
		ProxyURL: "http://configured-proxy.example.com:8080",
	}
	if _, errRegister := manager.Register(cliproxyauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	runtimeProxy := "http://runtime-proxy.example.com:9090"
	if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, cliproxyauth.RuntimeAuthOverride{ProxyURL: &runtimeProxy}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}
	runtimeAuth, okAuth := manager.GetByID(auth.ID)
	if !okAuth {
		t.Fatal("GetByID() did not find auth")
	}

	client := NewProxyAwareHTTPClient(context.Background(), nil, runtimeAuth, 0)
	transport, okTransport := client.Transport.(*http.Transport)
	if !okTransport || transport.Proxy == nil {
		t.Fatalf("transport = %T, want proxy-aware *http.Transport", client.Transport)
	}
	requestURL, errParse := url.Parse("https://example.com")
	if errParse != nil {
		t.Fatalf("url.Parse() error = %v", errParse)
	}
	proxyURL, errProxy := transport.Proxy(&http.Request{URL: requestURL})
	if errProxy != nil {
		t.Fatalf("transport.Proxy() error = %v", errProxy)
	}
	if proxyURL == nil || proxyURL.String() != runtimeProxy {
		t.Fatalf("transport.Proxy() = %v, want %q", proxyURL, runtimeProxy)
	}
}

func TestNewProxyAwareHTTPClientRuntimeDirectBypassesConfiguredProxy(t *testing.T) {
	t.Parallel()

	manager := cliproxyauth.NewManager(nil, nil, nil)
	auth := &cliproxyauth.Auth{
		ID:       "antigravity-runtime-direct",
		Provider: "antigravity",
		ProxyURL: "http://configured-proxy.example.com:8080",
	}
	if _, errRegister := manager.Register(cliproxyauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}
	direct := "direct"
	if _, errSet := manager.SetRuntimeAuthOverride(auth.Index, cliproxyauth.RuntimeAuthOverride{ProxyURL: &direct}); errSet != nil {
		t.Fatalf("SetRuntimeAuthOverride() error = %v", errSet)
	}
	runtimeAuth, okAuth := manager.GetByID(auth.ID)
	if !okAuth {
		t.Fatal("GetByID() did not find auth")
	}

	client := NewProxyAwareHTTPClient(
		context.Background(),
		&config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"}},
		runtimeAuth,
		0,
	)
	transport, okTransport := client.Transport.(*http.Transport)
	if !okTransport {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("runtime direct override did not disable configured proxies")
	}
}
