package live

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

func TestGroupingClientSecretTracksTrustedIssuerAndCannotOutliveRevocation(t *testing.T) {
	h, policy := groupingLiveFixture(t)
	router := gin.New()
	router.POST("/client_secrets", groupingLiveMiddleware, func(c *gin.Context) {
		c.Set("userApiKey", "spoofed-metadata")
		c.Set("accessProvider", "spoofed-provider")
	}, h.CreateClientSecret)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/client_secrets", strings.NewReader(`{"session":{"type":"realtime","model":"gpt-realtime"}}`)))
	var secret struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &secret); err != nil || response.Code != http.StatusOK || secret.Value == "" {
		t.Fatalf("issue status = %d, error = %v", response.Code, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/realtime?model=gpt-realtime", nil)
	request.Header.Set("Authorization", "Bearer "+secret.Value)
	issuer, matched, err := h.AuthenticateClientSecret(request)
	if err != nil || !matched || issuer.IssuerProvider != "test" || issuer.IssuerPrincipal != "live-issuer" {
		t.Fatalf("trusted issuer propagation failed: matched=%v error=%v", matched, err)
	}
	ctx := access.WithAuthenticatedPrincipal(context.Background(), issuer.IssuerProvider, issuer.IssuerPrincipal)
	watch, err := h.watchCredentialAccess(ctx, groupingLiveCredential(h))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watch.close(); <-watch.done }()
	policy.revoked.Store(true)
	h.authManager.NotifyCredentialAccessChanged()
	awaitGroupingClose(t, watch.done)
	if _, err = h.groupingClientSecretIssuer(ctx); err == nil {
		t.Fatal("revoked issuer can issue another secret")
	}
	if next, errNext := h.watchCredentialAccess(ctx, groupingLiveCredential(h)); errNext == nil {
		_ = next.close()
		t.Fatal("unexpired client secret bypassed issuer revocation")
	}
}
