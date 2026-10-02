package auth

import (
	"context"
	"sync"
	"testing"
)

func TestCredentialAccessChangeSubscription(t *testing.T) {
	m := NewManager(nil, nil, nil)
	changes, cancel := m.SubscribeCredentialAccessChanges()
	defer cancel()
	select {
	case <-changes:
		t.Fatal("unexpected initial notification")
	default:
	}
	m.SetCredentialAccessPolicy(&accessTestPolicy{scope: &accessTestScope{allowed: "allowed"}})
	select {
	case <-changes:
	default:
		t.Fatal("policy installation not notified")
	}
	for range 1000 {
		m.NotifyCredentialAccessChanged()
	}
	select {
	case <-changes:
	default:
		t.Fatal("policy update not notified")
	}
	select {
	case <-changes:
		t.Fatal("updates were not coalesced")
	default:
	}
	m.SetCredentialAccessPolicy(nil)
	select {
	case <-changes:
	default:
		t.Fatal("policy deactivation not notified")
	}
	cancel()
	cancel()
	if _, open := <-changes; open {
		t.Fatal("subscription not closed")
	}
	m.NotifyCredentialAccessChanged()
}

func TestCredentialAccessConcurrentSubscriptionAndPolicyChanges(t *testing.T) {
	m := NewManager(nil, nil, nil)
	policy := accessPolicyFunc(func(context.Context) (CredentialAccessScope, error) {
		return &accessTestScope{allowed: "allowed"}, nil
	})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				_, cancel := m.SubscribeCredentialAccessChanges()
				m.SetCredentialAccessPolicy(policy)
				m.NotifyCredentialAccessChanged()
				cancel()
			}
		})
	}
	workers.Wait()
}
