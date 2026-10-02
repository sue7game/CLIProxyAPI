package auth

import "sync"

type credentialAccessChanges struct {
	mu          sync.Mutex
	subscribers map[chan struct{}]struct{}
}

// SubscribeCredentialAccessChanges subscribes to policy invalidations.
// Notifications are coalesced; each notification requires a fresh authorization check.
// Subscribe before checking permission to avoid missing a concurrent update.
// The caller must cancel its subscription when its session ends. Cancel is idempotent.
func (m *Manager) SubscribeCredentialAccessChanges() (<-chan struct{}, func()) {
	if m == nil {
		return nil, func() {}
	}
	changes := &m.credentialAccessChanges
	events := make(chan struct{}, 1)
	changes.mu.Lock()
	if changes.subscribers == nil {
		changes.subscribers = make(map[chan struct{}]struct{})
	}
	changes.subscribers[events] = struct{}{}
	changes.mu.Unlock()
	return events, func() {
		changes.mu.Lock()
		defer changes.mu.Unlock()
		if _, subscribed := changes.subscribers[events]; subscribed {
			delete(changes.subscribers, events)
			close(events)
		}
	}
}

// NotifyCredentialAccessChanged invalidates policy-derived session permissions.
// Hosts must call this after publishing changed bindings, identities, or policy health.
// It performs no I/O, invokes no callbacks, and never waits for a consumer to read.
func (m *Manager) NotifyCredentialAccessChanged() {
	if m == nil {
		return
	}
	changes := &m.credentialAccessChanges
	changes.mu.Lock()
	defer changes.mu.Unlock()
	for events := range changes.subscribers {
		select {
		case events <- struct{}{}:
		default:
		}
	}
}
