package openai

import (
	"context"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
)

func TestGroupingVideoRejectsReusedOrLegacyUnknownIdentity(t *testing.T) {
	manager, policy := newGroupingSessionManager(t, "xai", "grouping-video-model")
	h := NewOpenAIAPIHandler(&handlers.BaseAPIHandler{AuthManager: manager})
	ctx := access.WithAuthenticatedPrincipal(context.Background(), "test", "session-token")
	original, _ := manager.GetByID(policy.authID)
	videoAuthBindings.setWithCredential("grouping-original-video", policy.authID, "", time.Hour, original)
	if _, err := h.groupedVideoCredential(ctx, "grouping-original-video"); err != nil {
		t.Fatal(err)
	}
	replacement := original.Clone()
	replacement.Attributes["grouping_id"] = "new-record"
	if _, err := manager.Register(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := h.groupedVideoCredential(ctx, "grouping-original-video"); err == nil {
		t.Fatal("runtime ID reuse exposed an old video via a different source")
	}
	videoAuthBindings.set("grouping-legacy-video", policy.authID, time.Hour)
	if _, err := h.groupedVideoCredential(ctx, "grouping-legacy-video"); err == nil {
		t.Fatal("legacy binding without a permanent identity was accepted")
	}
	manager.SetCredentialAccessPolicy(nil)
	if _, err := h.authorizedVideoContext(ctx, "grouping-legacy-video"); err != nil {
		t.Fatal(err)
	}
}
