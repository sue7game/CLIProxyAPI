package management

import (
	"context"
	"testing"
)

func TestConfigApplyRejectsInvalidTokenRotations(t *testing.T) {
	for _, body := range []string{
		`{"old":"missing","new":"new-token"}`,
		`{"old":"old-token","new":" "}`,
		`{"old":"old-token","new":" new-token "}`,
		`{"index":0,"value":"new-token","old":"other-token","new":"new-token"}`,
		`{"index":0,"value":"new-token","old":"old-token","new":"other-token"}`,
	} {
		t.Run(body, func(t *testing.T) {
			h, source, raw := newConfigApplyTestHandler(t)
			h.SetConfigApplyHook(func(_ context.Context, _ ConfigApplyRequest) error {
				t.Fatal("invalid rotation reached transaction hook")
				return nil
			})
			response := configApplyRequest(h, "PATCH", "/api-keys", body)
			if response.Code < 400 || response.Code >= 500 {
				t.Fatalf("status = %d", response.Code)
			}
			assertConfigApplyUnchanged(t, h, source, raw)
		})
	}
}

func TestConfigApplyNoopRotationCannotHideOtherChanges(t *testing.T) {
	err := validateAPIKeyTransition([]string{"old-token"}, []string{"old-token", "unrelated"}, &APIKeyRotation{Old: "old-token", New: "old-token"})
	if err == nil {
		t.Fatal("unrelated changes hidden by no-op rotation")
	}
}
