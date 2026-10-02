package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

type credentialApplyCase struct {
	name               string
	field              string
	put, patch, delete func(*Handler, *gin.Context)
	get                func(*Handler, *gin.Context)
}

func credentialApplyCases() []credentialApplyCase {
	return []credentialApplyCase{
		{"gemini", "gemini-api-key", (*Handler).PutGeminiKeys, (*Handler).PatchGeminiKey, (*Handler).DeleteGeminiKey, (*Handler).GetGeminiKeys},
		{"interactions", "interactions-api-key", (*Handler).PutInteractionsKeys, (*Handler).PatchInteractionsKey, (*Handler).DeleteInteractionsKey, (*Handler).GetInteractionsKeys},
		{"claude", "claude-api-key", (*Handler).PutClaudeKeys, (*Handler).PatchClaudeKey, (*Handler).DeleteClaudeKey, (*Handler).GetClaudeKeys},
		{"codex", "codex-api-key", (*Handler).PutCodexKeys, (*Handler).PatchCodexKey, (*Handler).DeleteCodexKey, (*Handler).GetCodexKeys},
		{"xai", "xai-api-key", (*Handler).PutXAIKeys, (*Handler).PatchXAIKey, (*Handler).DeleteXAIKey, (*Handler).GetXAIKeys},
		{"meta", "meta-api-key", (*Handler).PutMetaKeys, (*Handler).PatchMetaKey, (*Handler).DeleteMetaKey, (*Handler).GetMetaKeys},
		{"vertex", "vertex-api-key", (*Handler).PutVertexCompatKeys, (*Handler).PatchVertexCompatKey, (*Handler).DeleteVertexCompatKey, (*Handler).GetVertexCompatKeys},
		{"compat", "openai-compatibility", (*Handler).PutOpenAICompat, (*Handler).PatchOpenAICompat, (*Handler).DeleteOpenAICompat, (*Handler).GetOpenAICompat},
	}
}

const credentialApplyID = "62d65556-c485-41b0-870c-f449c011b941"
const credentialApplyJSON = `{"api-key":"source-key","name":"provider","base-url":"https://example.test","grouping-id":"` + credentialApplyID + `"}`

func credentialApplyFixture(t *testing.T, field string) (*Handler, *config.Config, []byte) {
	t.Helper()
	h, source, raw := newConfigApplyTestHandler(t)
	if err := json.Unmarshal([]byte(`{"`+field+`":[`+credentialApplyJSON+`]}`), source); err != nil {
		t.Fatal(err)
	}
	return h, source, raw
}

func invokeConfigMutation(h *Handler, fn func(*Handler, *gin.Context), method, target, body string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	fn(h, c)
	return response
}

func TestConfigApplyEveryCredentialCRUDUsesIsolatedTransaction(t *testing.T) {
	for _, tc := range credentialApplyCases() {
		for _, op := range []struct {
			method, body string
			fn           func(*Handler, *gin.Context)
		}{
			{"PUT", "[" + credentialApplyJSON + "]", tc.put},
			{"PATCH", `{"index":0,"value":{"prefix":"changed"}}`, tc.patch},
			{"DELETE", "", tc.delete},
		} {
			t.Run(tc.name+"/"+op.method, func(t *testing.T) {
				h, source, raw := credentialApplyFixture(t, tc.field)
				before := source.CloneForRuntime()
				called := false
				h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
					called = true
					if req.Current == source || req.Proposed == source || !reflect.DeepEqual(before, source) {
						t.Fatal("shared config mutated before hook")
					}
					return errors.New("reject")
				})
				response := invokeConfigMutation(h, op.fn, op.method, "/credential?index=0", op.body)
				if !called || response.Code != 500 {
					t.Fatalf("called=%v status=%d body=%s", called, response.Code, response.Body.String())
				}
				assertConfigApplyUnchanged(t, h, source, raw)
				if !reflect.DeepEqual(before, source) {
					t.Fatal("candidate mutated source configuration")
				}
			})
		}
	}
}

func TestConfigApplyCredentialGETAndPatchPreserveGroupingID(t *testing.T) {
	for _, tc := range credentialApplyCases() {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := credentialApplyFixture(t, tc.field)
			h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
				if err := config.ValidateGroupingCredentialIDs(req.Proposed); err != nil {
					t.Fatal(err)
				}
				h.SetConfig(req.Proposed.CloneForRuntime())
				return nil
			})
			response := invokeConfigMutation(h, tc.patch, "PATCH", "/credential", `{"index":0,"value":{"prefix":"changed"}}`)
			if response.Code != 200 {
				t.Fatalf("patch status=%d", response.Code)
			}
			response = invokeConfigMutation(h, tc.get, "GET", "/credential", "")
			if !strings.Contains(response.Body.String(), `"grouping-id":"`+credentialApplyID+`"`) {
				t.Fatal("GET omitted stable identity")
			}
		})
	}
}

func TestConfigApplyYAMLRejectsBeforeDiskOrSharedMutation(t *testing.T) {
	h, source, raw := newConfigApplyTestHandler(t)
	called := false
	h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
		called = true
		if req.Operation != "config.yaml.put" || !req.Proposed.Debug {
			t.Fatal("incorrect YAML candidate")
		}
		return errors.New("reject")
	})
	response := invokeConfigMutation(h, (*Handler).PutConfigYAML, "PUT", "/config.yaml", string(raw)+"debug: true\n")
	if !called || response.Code != 500 {
		t.Fatalf("called=%v status=%d", called, response.Code)
	}
	assertConfigApplyUnchanged(t, h, source, raw)
	entries, err := os.ReadDir(filepath.Dir(h.configFilePath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatal("YAML transaction created files before validation")
	}
}
