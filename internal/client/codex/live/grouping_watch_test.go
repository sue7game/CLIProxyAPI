package live

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestGroupingRealtimeWatchRevocationAndStoreFailure(t *testing.T) {
	for _, failure := range []string{"issuer-revoked", "policy-broken", "credential-disabled"} {
		t.Run(failure, func(t *testing.T) {
			h, policy := groupingLiveFixture(t)
			watch, err := h.watchCredentialAccess(groupingLiveContext(), groupingLiveCredential(h))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = watch.close(); <-watch.done }()
			closed := make(chan struct{})
			watch.resources.add(func() error { close(closed); return nil })
			switch failure {
			case "issuer-revoked":
				policy.revoked.Store(true)
			case "policy-broken":
				policy.broken.Store(true)
			case "credential-disabled":
				registerCredential(t, h.authManager, &auth.Auth{ID: "grouping-live-auth", Provider: "codex", Disabled: true})
			}
			h.authManager.NotifyCredentialAccessChanged()
			awaitGroupingClose(t, closed)
			if watch.currentError() == nil {
				t.Fatal("revoked watcher reports success")
			}
		})
	}
}

func TestGroupingRealtimeWatchRequiresTrustedIssuer(t *testing.T) {
	h, _ := groupingLiveFixture(t)
	if watch, err := h.watchCredentialAccess(context.Background(), groupingLiveCredential(h)); err == nil {
		_ = watch.close()
		t.Fatal("anonymous retained watch accepted")
	}
}

func TestGroupingRealtimeWatchRetainedLifetimeAndLateResource(t *testing.T) {
	h, policy := groupingLiveFixture(t)
	ctx, cancelRequest := context.WithCancel(groupingLiveContext())
	watch, err := h.watchCredentialAccess(ctx, groupingLiveCredential(h))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watch.close(); <-watch.done }()
	cancelRequest()
	if watch.ctx.Err() != nil || watch.currentError() != nil {
		t.Fatal("retained permission inherited completed HTTP request cancellation")
	}
	policy.revoked.Store(true)
	h.authManager.NotifyCredentialAccessChanged()
	awaitGroupingClose(t, watch.done)
	closed := make(chan struct{})
	watch.resources.add(func() error { close(closed); return nil })
	awaitGroupingClose(t, closed)
}

func TestGroupingRealtimeLegacySessionObservesActivation(t *testing.T) {
	h, policy := groupingLiveFixture(t)
	h.authManager.SetCredentialAccessPolicy(nil)
	watch, err := h.watchCredentialAccess(context.Background(), groupingLiveCredential(h))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watch.close(); <-watch.done }()
	closed := make(chan struct{})
	watch.resources.add(func() error { close(closed); return nil })
	h.authManager.SetCredentialAccessPolicy(policy)
	awaitGroupingClose(t, closed)
}
