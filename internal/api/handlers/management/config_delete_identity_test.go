package management

import (
	"context"
	"net/url"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

const otherDeleteIdentity = "45b66f30-d5f5-4c6f-8a8a-bf88b74ff677"

func TestCredentialDeleteIdentityPrecondition(t *testing.T) {
	for _, tc := range credentialApplyCases() {
		for _, id := range []string{credentialApplyID, otherDeleteIdentity} {
			t.Run(tc.name+"/"+id, func(t *testing.T) {
				h, source, raw := credentialApplyFixture(t, tc.field)
				before := source.CloneForRuntime()
				called := false
				h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
					called = true
					h.SetConfig(req.Proposed.CloneForRuntime())
					return nil
				})
				response := invokeConfigMutation(h, tc.delete, "DELETE", "/credential?index=0&grouping-id="+id, "")
				if id == credentialApplyID {
					if !called || response.Code != 200 {
						t.Fatalf("called=%v status=%d", called, response.Code)
					}
				} else {
					if called || response.Code != 409 {
						t.Fatalf("called=%v status=%d", called, response.Code)
					}
					assertConfigApplyUnchanged(t, h, source, raw)
				}
				if !reflect.DeepEqual(source, before) {
					t.Fatal("shared source mutated")
				}
			})
		}
	}
}

func TestCredentialDeleteIdentityCannotFallBackToAnotherSelector(t *testing.T) {
	for _, query := range []string{
		"index=1&grouping-id=" + credentialApplyID,
		"index=-1&grouping-id=" + credentialApplyID,
		"index=0&grouping-id=",
		"grouping-id=" + credentialApplyID,
		"index=0&api-key=another-key&grouping-id=" + credentialApplyID,
		"index=0&grouping-ids=[]",
	} {
		h, source, raw := credentialApplyFixture(t, "gemini-api-key")
		h.SetConfigApplyHook(func(context.Context, ConfigApplyRequest) error {
			t.Fatal("invalid precondition reached hook")
			return nil
		})
		response := invokeConfigMutation(h, (*Handler).DeleteGeminiKey, "DELETE", "/credential?"+query, "")
		if response.Code < 400 || response.Code >= 500 {
			t.Fatalf("query=%s status=%d", query, response.Code)
		}
		assertConfigApplyUnchanged(t, h, source, raw)
	}
}

func TestOpenAIProviderDeleteUsesCompleteNonsecretChildIdentitySet(t *testing.T) {
	for _, ids := range []string{
		`["` + credentialApplyID + `","` + otherDeleteIdentity + `"]`,
		`["` + otherDeleteIdentity + `","` + credentialApplyID + `"]`,
		`["` + credentialApplyID + `"]`,
		`["` + credentialApplyID + `","` + credentialApplyID + `"]`,
		`[]`,
	} {
		t.Run(ids, func(t *testing.T) {
			h, source, _ := newConfigApplyTestHandler(t)
			source.OpenAICompatibility = []config.OpenAICompatibility{{Name: "provider", APIKeyEntries: []config.OpenAICompatibilityAPIKey{
				{APIKey: "first-secret", GroupingID: credentialApplyID}, {APIKey: "second-secret", GroupingID: otherDeleteIdentity},
			}}}
			called := false
			h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
				called = true
				h.SetConfig(req.Proposed.CloneForRuntime())
				return nil
			})
			response := invokeConfigMutation(h, (*Handler).DeleteOpenAICompat, "DELETE", "/credential?index=0&grouping-ids="+url.QueryEscape(ids), "")
			valid := ids == `["`+credentialApplyID+`","`+otherDeleteIdentity+`"]` || ids == `["`+otherDeleteIdentity+`","`+credentialApplyID+`"]`
			if valid {
				if !called || response.Code != 200 || len(h.cfg.OpenAICompatibility) != 0 {
					t.Fatalf("status=%d", response.Code)
				}
			} else if called || response.Code != 409 || len(h.cfg.OpenAICompatibility) != 1 {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}
}

func TestCredentialDeleteLegacyRequestNeedsNoIdentity(t *testing.T) {
	h, source, _ := credentialApplyFixture(t, "gemini-api-key")
	source.Grouping.Enabled = false
	source.GeminiKey[0].GroupingID = ""
	response := invokeConfigMutation(h, (*Handler).DeleteGeminiKey, "DELETE", "/credential?index=0", "")
	if response.Code != 200 || len(h.cfg.GeminiKey) != 0 {
		t.Fatalf("legacy delete status=%d", response.Code)
	}
}
