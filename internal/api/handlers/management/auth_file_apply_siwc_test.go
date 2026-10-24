package management

import (
	"context"
	"net/http"
	"testing"
)

func TestAuthFileApplyKeepsSIWCMutationFence(t *testing.T) {
	f := setupSIWCFlow(t, false)
	f.router.POST("/credentials", f.h.UploadAuthFileV8)
	state, flow := f.start(t)
	called := false
	f.h.SetAuthFileApplyHook(func(_ context.Context, path string, _ []byte) error {
		called = true
		if path != f.path || flow.ctx.Err() == nil || f.store.IsPending(state, "codex") {
			t.Fatal("upload transaction began before invalidating the pending SIWC binding")
		}
		if f.h.siwcCommitMu.TryLock() {
			f.h.siwcCommitMu.Unlock()
			t.Fatal("upload transaction did not hold the SIWC commit gate")
		}
		return nil
	})
	response := siwcRequest(t, f.router, http.MethodPost, "/credentials?name=codex.json", f.auth.Metadata)
	if response.Code != http.StatusOK || !called {
		t.Fatalf("grouping upload hook failed: %d %s", response.Code, response.Body.String())
	}
}
