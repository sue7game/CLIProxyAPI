package management

import (
	"bytes"
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

func TestConfigV8GroupingPutPatchYAMLPreserveIDs(t *testing.T) {
	cases := []struct{ method, path, body string }{
		{"PUT", "/v8/management/config/api-keys/codex", v8GroupingSources},
		{"PATCH", "/v8/management/config", `{"api-keys":{"codex":` + v8GroupingSources + `}}`},
		{"PUT", "/v8/management/config.yaml", v8GroupingDocument},
	}
	for _, tc := range cases {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			f := newV8GroupingFixture(t, v8GroupingDocument)
			before := f.read(t)
			response := f.request(tc.method, tc.path, tc.body, f.etag(t))
			if response.Code != http.StatusOK || len(f.calls) != 1 {
				t.Fatalf("mutation failed: %d %s", response.Code, response.Body.String())
			}
			if !bytes.Equal(f.calls[0].SourceYAML, before) || len(f.calls[0].CanonicalYAML) == 0 {
				t.Fatal("mutation omitted canonical or source bytes")
			}
			assertV8GroupingRetainedFields(t, f)
			if len(f.h.cfg.CodexKey) != 2 || f.h.cfg.CodexKey[0].GroupingID != v8GroupingIDFirst || f.h.cfg.CodexKey[1].GroupingID != v8GroupingIDSecond {
				t.Fatal("runtime publication lost source identities")
			}
		})
	}
}

func TestConfigV8GroupingDeletesRequireCurrentSelection(t *testing.T) {
	f := newV8GroupingFixture(t, v8GroupingDocument)
	before := f.read(t)
	for _, tc := range []struct {
		header string
		status int
	}{{"", 428}, {`"stale"`, 412}, {"*", 412}} {
		response := f.request("DELETE", "/v8/management/config/api-keys/codex", "", tc.header)
		if response.Code != tc.status || !bytes.Equal(f.read(t), before) || len(f.calls) != 0 {
			t.Fatalf("unsafe deletion not rejected: status %d", response.Code)
		}
	}
	response := f.request("DELETE", "/v8/management/config/api-keys/codex", "", f.etag(t))
	if response.Code != 200 || len(f.h.cfg.CodexKey) != 0 || len(f.calls) != 1 {
		t.Fatalf("identity-checked deletion failed: %d %s", response.Code, response.Body.String())
	}
}

func TestConfigV8GroupingTokenRotationIsExplicit(t *testing.T) {
	f := newV8GroupingFixture(t, v8GroupingDocument)
	before := f.read(t)
	response := f.request("PUT", "/v8/management/config/access/api-keys", `["replacement-token","second-token"]`, f.etag(t))
	if response.Code != 409 || len(f.calls) != 0 || !bytes.Equal(before, f.read(t)) {
		t.Fatal("implicit token replacement was accepted")
	}
	response = f.request("PATCH", "/v8/management/access/api-keys", `{"old":"first-token","new":"replacement-token"}`, "")
	if response.Code != 200 || len(f.calls) != 1 {
		t.Fatalf("explicit rotation failed: %d %s", response.Code, response.Body.String())
	}
	rotation := f.calls[0].TokenRotation
	if rotation == nil || rotation.Old != "first-token" || rotation.New != "replacement-token" || f.h.cfg.APIKeys[0] != "replacement-token" {
		t.Fatal("explicit rotation metadata was lost")
	}
	assertV8GroupingRetainedFields(t, f)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"old":"missing-token","new":"new-token"}`, 404},
		{`{"index":0,"value":"new-token"}`, 400},
	} {
		if response = f.request("PATCH", "/v8/management/access/api-keys", tc.body, ""); response.Code != tc.status {
			t.Fatalf("invalid rotation returned %d", response.Code)
		}
	}
}

func TestConfigV8GroupingFailureCannotPublishOrPersist(t *testing.T) {
	for _, installed := range []bool{false, true} {
		f := newV8GroupingFixture(t, v8GroupingDocument)
		before, previous := f.read(t), f.h.cfg.CloneForRuntime()
		f.h.SetConfigApplyHook(nil)
		if installed {
			f.h.SetConfigApplyHook(func(context.Context, ConfigApplyRequest) error {
				return &ConfigApplyError{503, "grouping_unavailable", "publication unavailable"}
			})
		}
		response := f.request("PATCH", "/v8/management/config", `{"routing":{"retry":{"request-retry":6}}}`, "")
		if response.Code != 503 || !bytes.Equal(before, f.read(t)) || !reflect.DeepEqual(previous, f.h.cfg) {
			t.Fatal("failed mutation persisted or published a candidate")
		}
	}
}

func TestConfigV8GroupingNewDuplicateRecordsRemainIndependent(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		raw := v8GroupingDocument
		if !enabled {
			raw = strings.Replace(raw, "grouping: {enabled: true", "grouping: {enabled: false", 1)
		}
		f := newV8GroupingFixture(t, raw)
		body := strings.Replace(v8GroupingSources, `]}]`, `,{"api-key":"new-duplicate"},{"api-key":"new-duplicate"}]}]`, 1)
		response := f.request("PUT", "/v8/management/config/api-keys/codex", body, "")
		if response.Code != 200 || len(f.h.cfg.CodexKey) != 4 {
			t.Fatalf("duplicate sources were lost: %d %s", response.Code, response.Body.String())
		}
		if f.h.cfg.CodexKey[2].GroupingID == f.h.cfg.CodexKey[3].GroupingID {
			t.Fatal("duplicate sources share an identity")
		}
		if err := config.ValidateGroupingCredentialIDs(f.h.cfg); err != nil {
			t.Fatal(err)
		}
	}
}

func assertV8GroupingRetainedFields(t *testing.T, f *v8GroupingFixture) {
	t.Helper()
	raw := f.read(t)
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	root := doc.Content[0]
	for _, path := range [][]string{{"requests", "payload", "default"}, {"plugins", "configs", "sample", "custom", "nullable"}} {
		if node := configV8Node(root, path); node == nil || node.Tag != "!!null" {
			t.Fatal("explicit null field was lost", path)
		}
	}
	empty := configV8Node(root, []string{"plugins", "configs", "sample", "custom", "empty"})
	if empty == nil || empty.Kind != yaml.MappingNode || len(empty.Content) != 0 {
		t.Fatal("explicit empty plugin map was lost")
	}
	servers := configV8Node(root, v8ICEServersPath)
	if servers == nil || len(servers.Content) != 1 || configV8Node(servers.Content[0], []string{"username"}).Value != "retained-user" || configV8Node(servers.Content[0], []string{"credential"}).Value != "retained-secret" {
		t.Fatal("TURN credentials were lost")
	}
	if err := config.ValidateV8Config(raw); err != nil {
		t.Fatal(err)
	}
}
