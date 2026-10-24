package management

import "context"

// AuthFileApplyHook validates and atomically commits an uploaded credential and
// its policy before publishing it. Raw contains secrets and must never be logged.
// The hook owns parsing, persistence, runtime registration, and reconciliation.
// An installed hook is called even while grouping is disabled, so its owner must
// preserve legacy behavior when no grouping transaction is required.
type AuthFileApplyHook func(ctx context.Context, path string, raw []byte) error

// SetAuthFileApplyHook installs the synchronous credential upload transaction.
func (h *Handler) SetAuthFileApplyHook(hook AuthFileApplyHook) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.authFileApplyHook = hook
	h.mu.Unlock()
}
