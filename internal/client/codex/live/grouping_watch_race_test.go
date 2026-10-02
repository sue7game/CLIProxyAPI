package live

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type initialGroupingCheckPolicy struct {
	liveGroupingPolicy
	checks  atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (p *initialGroupingCheckPolicy) BeginAttempt(ctx context.Context) (auth.CredentialAccessScope, error) {
	// Both halves of the first retained-credential check may finish from an old
	// snapshot. Its subscription must already exist when that snapshot is read.
	switch p.checks.Add(1) {
	case 1:
		close(p.entered)
		<-p.release
		return initialGroupingCheckScope{}, nil
	case 2:
		return initialGroupingCheckScope{}, nil
	default:
		return p.liveGroupingPolicy.BeginAttempt(ctx)
	}
}

type initialGroupingCheckScope struct{}

func (initialGroupingCheckScope) Allows(a *auth.Auth) bool                       { return a != nil }
func (initialGroupingCheckScope) AuthorizeUse(context.Context, *auth.Auth) error { return nil }

func TestGroupingWatchSubscribesBeforeFirstCheck(t *testing.T) {
	h, _ := groupingLiveFixture(t)
	p := &initialGroupingCheckPolicy{entered: make(chan struct{}), release: make(chan struct{})}
	h.authManager.SetCredentialAccessPolicy(p)
	ready := make(chan *credentialAccessWatch, 1)
	failure := make(chan error, 1)
	go func() {
		watch, err := h.watchCredentialAccess(groupingLiveContext(), groupingLiveCredential(h))
		if err != nil {
			failure <- err
			return
		}
		ready <- watch
	}()
	awaitGroupingClose(t, p.entered)
	p.revoked.Store(true)
	h.authManager.NotifyCredentialAccessChanged()
	close(p.release)
	select {
	case err := <-failure:
		t.Fatal(err)
	case watch := <-ready:
		defer func() { _ = watch.close() }()
		awaitGroupingClose(t, watch.done)
		if watch.currentError() == nil {
			t.Fatal("missed revocation during initial check")
		}
	}
}

func TestGroupingWatchPinsPermanentCredentialIdentity(t *testing.T) {
	h, _ := groupingLiveFixture(t)
	original := groupingLiveCredential(h)
	watch, err := h.watchCredentialAccess(groupingLiveContext(), original)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watch.close(); <-watch.done }()
	replacement := original.Clone()
	replacement.Attributes["grouping_id"] = "f2147f90-0c75-40b6-8d54-dba8a2d70d25"
	registerCredential(t, h.authManager, replacement)
	closed := make(chan struct{})
	watch.resources.add(func() error { close(closed); return nil })
	h.authManager.NotifyCredentialAccessChanged()
	awaitGroupingClose(t, closed)
	if watch.currentError() == nil {
		t.Fatal("runtime ID reuse kept old media authorized")
	}
}

func TestGroupingWatchFrameCheckClosesResourcesWithoutWaitingForBroadcast(t *testing.T) {
	h, policy := groupingLiveFixture(t)
	watch, err := h.watchCredentialAccess(groupingLiveContext(), groupingLiveCredential(h))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watch.close(); <-watch.done }()
	closed := make(chan struct{})
	watch.resources.add(func() error { close(closed); return nil })
	policy.revoked.Store(true)
	if watch.currentError() == nil {
		t.Fatal("revoked frame check accepted")
	}
	awaitGroupingClose(t, closed)
}

func TestGroupingWatchConcurrentBroadcastRetainAndClose(t *testing.T) {
	h, policy := groupingLiveFixture(t)
	for range 64 {
		policy.revoked.Store(false)
		watch, err := h.watchCredentialAccess(groupingLiveContext(), groupingLiveCredential(h))
		if err != nil {
			t.Fatal(err)
		}
		var closes atomic.Int32
		var tasks sync.WaitGroup
		tasks.Add(3)
		go func() { defer tasks.Done(); watch.resources.add(func() error { closes.Add(1); return nil }) }()
		go func() {
			defer tasks.Done()
			policy.revoked.Store(true)
			for range 32 {
				h.authManager.NotifyCredentialAccessChanged()
			}
		}()
		go func() { defer tasks.Done(); _ = watch.currentError() }()
		tasks.Wait()
		awaitGroupingClose(t, watch.done)
		_ = watch.close()
		if closes.Load() != 1 {
			t.Fatalf("resource closed %d times", closes.Load())
		}
	}
}
