package live

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type liveGroupingPolicy struct {
	revoked atomic.Bool
	broken  atomic.Bool
}

func (p *liveGroupingPolicy) BeginAttempt(ctx context.Context) (auth.CredentialAccessScope, error) {
	principal, exists := access.AuthenticatedPrincipalFromContext(ctx)
	if p.broken.Load() {
		return nil, &auth.Error{Message: "policy unavailable", HTTPStatus: http.StatusServiceUnavailable}
	}
	if !exists || principal.Subject != "live-issuer" || p.revoked.Load() {
		return nil, &auth.Error{Message: "issuer denied", HTTPStatus: http.StatusForbidden}
	}
	return p, nil
}

func (p *liveGroupingPolicy) Allows(a *auth.Auth) bool {
	return a != nil && a.ID == "grouping-live-auth"
}

func (p *liveGroupingPolicy) AuthorizeUse(ctx context.Context, a *auth.Auth) error {
	if _, err := p.BeginAttempt(ctx); err != nil {
		return err
	}
	if !p.Allows(a) {
		return &auth.Error{Message: "credential denied", HTTPStatus: http.StatusForbidden}
	}
	return nil
}

func groupingLiveFixture(t *testing.T) (*Handler, *liveGroupingPolicy) {
	t.Helper()
	m := auth.NewManager(nil, nil, nil)
	registerCredential(t, m, &auth.Auth{ID: "grouping-live-auth", Provider: "codex",
		Attributes: map[string]string{"grouping_id": "c170b319-882f-4b69-a0b7-f1262e8d80a9"},
		Metadata:   map[string]any{"access_token": "test-only"}})
	p := &liveGroupingPolicy{}
	m.SetCredentialAccessPolicy(p)
	h := NewHandler(m, nil)
	t.Cleanup(h.Close)
	return h, p
}

func groupingLiveContext() context.Context {
	return access.WithAuthenticatedPrincipal(context.Background(), "test", "live-issuer")
}

func groupingLiveCredential(h *Handler) *auth.Auth {
	credential, _ := h.authManager.GetByID("grouping-live-auth")
	return credential
}

func groupingLiveMiddleware(c *gin.Context) {
	c.Request = c.Request.WithContext(access.WithAuthenticatedPrincipal(c.Request.Context(), "test", "live-issuer"))
}

func awaitGroupingClose(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("authorization revocation did not close the resource")
	}
}

type groupingMediaSession struct {
	mu      sync.Mutex
	handler func(string)
	closed  atomic.Bool
	done    chan struct{}
}

func (s *groupingMediaSession) AcceptUpstreamAnswer(context.Context, string) (string, error) {
	return "v=0\r\no=grouping-answer\r\n", nil
}

func (*groupingMediaSession) SetCallID(string) {}

func (s *groupingMediaSession) SetCloseHandler(handler func(string)) {
	s.mu.Lock()
	s.handler = handler
	s.mu.Unlock()
}

func (s *groupingMediaSession) Close() error { return s.CloseWithReason("closed") }

func (s *groupingMediaSession) CloseWithReason(reason string) error {
	if s.closed.Swap(true) {
		return nil
	}
	s.mu.Lock()
	handler := s.handler
	s.mu.Unlock()
	if handler != nil {
		handler(reason)
	}
	close(s.done)
	return nil
}

type groupingMediaRelay struct{ session *groupingMediaSession }

func (r *groupingMediaRelay) NewSession(context.Context, string, mediaSessionRoute) (mediaRelaySession, string, error) {
	return r.session, "v=0\r\no=grouping-offer\r\n", nil
}
