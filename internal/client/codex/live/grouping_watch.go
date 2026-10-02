package live

import (
	"context"
	"net/http"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type credentialAccessWatch struct {
	manager     *auth.Manager
	credential  *auth.Auth
	principal   context.Context
	ctx         context.Context
	cancel      context.CancelFunc
	unsubscribe func()
	resources   liveSessionResources
	mu          sync.Mutex
	err         error
	done        chan struct{}
}

func (h *Handler) watchCredentialAccess(ctx context.Context, credential *auth.Auth) (*credentialAccessWatch, error) {
	principal := access.CopyAuthenticatedPrincipal(context.Background(), ctx)
	lifetime, cancel := context.WithCancel(context.Background())
	events, unsubscribe := h.authManager.SubscribeCredentialAccessChanges()
	w := &credentialAccessWatch{
		manager: h.authManager, credential: credential.Clone(), principal: principal,
		ctx: lifetime, cancel: cancel, unsubscribe: unsubscribe, done: make(chan struct{}),
	}
	if err := w.check(); err != nil {
		cancel()
		unsubscribe()
		return nil, err
	}
	go w.run(events)
	return w, nil
}

func (w *credentialAccessWatch) check() error {
	if !w.manager.CredentialAccessPolicyEnabled() {
		return nil
	}
	_, err := handlers.AuthorizeRetainedCredential(w.principal, w.manager, w.credential)
	return err
}

func (w *credentialAccessWatch) run(events <-chan struct{}) {
	defer close(w.done)
	for {
		select {
		case <-w.ctx.Done():
			return
		case _, open := <-events:
			if w.ctx.Err() != nil {
				return
			}
			err := w.check()
			if !open {
				err = &auth.Error{Code: "credential_policy_unavailable", Message: "Realtime authorization monitor unavailable", HTTPStatus: http.StatusServiceUnavailable}
			}
			if err != nil {
				w.revoke(err)
				return
			}
		}
	}
}

func (w *credentialAccessWatch) currentError() error {
	w.mu.Lock()
	err := w.err
	w.mu.Unlock()
	if err != nil {
		return err
	}
	if err = w.ctx.Err(); err != nil {
		return err
	}
	if err = w.check(); err != nil {
		w.revoke(err)
	}
	return err
}

func (w *credentialAccessWatch) revoke(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
	w.cancel()
	w.unsubscribe()
	w.resources.close()
}

func (w *credentialAccessWatch) close() error {
	w.cancel()
	w.unsubscribe()
	return nil
}

func (w *credentialAccessWatch) requestContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(w.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

func (w *credentialAccessWatch) retain(h *Handler, session liveSession) error {
	session.resources.add(w.close)
	w.resources.add(func() error {
		h.sessions.complete(session, "credential_access_revoked")
		return nil
	})
	return w.currentError()
}
