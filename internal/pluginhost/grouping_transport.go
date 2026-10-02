package pluginhost

import (
	"net/http"

	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type groupingHTTPTransport struct {
	client *hostHTTPClient
	base   http.RoundTripper
}

// RoundTrip checks every wire request, including HTTP redirects, before use.
func (t groupingHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.client.host.authorizeHostHTTP(req.Context(), t.client.auth); err != nil {
		return nil, err
	}
	coreexecutor.MarkUpstreamAttempt(req.Context())
	return t.base.RoundTrip(req)
}

func (c *hostHTTPClient) withCredentialAccessTransport(client *http.Client) *http.Client {
	guarded := *client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	guarded.Transport = groupingHTTPTransport{client: c, base: base}
	return &guarded
}
