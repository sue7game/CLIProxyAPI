package groupingapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func captureAudit(t *testing.T) *logtest.Hook {
	t.Helper()
	logger := log.StandardLogger()
	output, level := logger.Out, logger.GetLevel()
	hooks := logger.ReplaceHooks(make(log.LevelHooks))
	hook := &logtest.Hook{}
	logger.AddHook(hook)
	logger.SetOutput(io.Discard)
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.ReplaceHooks(hooks)
		logger.SetOutput(output)
		logger.SetLevel(level)
	})
	return hook
}

func TestAuditAllowlistNeverLogsUntrustedText(t *testing.T) {
	hook := captureAudit(t)
	secret := "Bearer private-secret-fingerprint\nforged log entry"
	AuditRecord{Action: Operation(secret), Namespace: secret, Revision: 8,
		LogicalIDs: []string{secret, queryGroup, queryGroup}, ConfirmationReason: secret,
		GroupChanges: []AuditGroupChange{{ID: queryGroup, OldGroup: "all", NewGroup: queryGroup},
			{ID: secret, OldGroup: "all", NewGroup: queryGroup}, {ID: queryGroup, OldGroup: secret, NewGroup: "all"}},
	}.Log(false)
	entry := hook.LastEntry()
	if entry.Level != log.WarnLevel || entry.Message != "grouping management mutation failed" || entry.Data["action"] != Operation("unknown") {
		t.Fatalf("unexpected event: %+v", entry)
	}
	data, err := json.Marshal(entry.Data)
	if err != nil || strings.Contains(string(data), "private-secret") || len(entry.Data) != 4 {
		t.Fatalf("audit leaked untrusted data: %s %v", data, err)
	}
	if ids := entry.Data["logical_ids"].([]string); len(ids) != 1 || ids[0] != queryGroup {
		t.Fatalf("unsafe logical IDs: %v", ids)
	}
	if changes := entry.Data["group_changes"].([]AuditGroupChange); len(changes) != 1 {
		t.Fatalf("unsafe changes: %v", changes)
	}
}

func TestRejectedHTTPMutationsAreAuditedWithoutRequestData(t *testing.T) {
	hook := captureAudit(t)
	tests := []struct{ method, path, body, revision string }{
		{http.MethodPost, "/initialize", `{"secret":"private-secret"}`, ""},
		{http.MethodPatch, "/activation", `{"enabled":true}`, "private-secret"},
		{http.MethodPost, "/groups", `{"name":"private-secret","unexpected":true}`, `"7"`},
		{http.MethodDelete, "/groups/private-secret", `{}`, `"7"`},
		{http.MethodPatch, "/bindings", `{"token_ids":["private-secret"],"group_id":" "}`, `"7"`},
		{http.MethodPost, "/bindings/rebind", `{"id":"private-secret","confirm":false}`, `"7"`},
	}
	for _, test := range tests {
		hook.Reset()
		backend := newBackend()
		response := perform(testRouter(backend), test.method, test.path, test.body, test.revision)
		if response.Code < 400 || backend.calls != 0 || len(hook.AllEntries()) != 1 {
			t.Fatalf("rejected request was not audited: %d %+v", response.Code, hook.AllEntries())
		}
		entry := hook.LastEntry()
		if len(entry.Data) != 2 || entry.Data["revision"] != uint64(0) {
			t.Fatalf("unvalidated request metadata reached log: %+v", entry.Data)
		}
	}
	hook.Reset()
	perform(testRouter(newBackend()), http.MethodGet, "/credentials?group_id=secret", "", "")
	if len(hook.AllEntries()) != 0 {
		t.Fatal("a rejected read is not a mutation audit event")
	}
}

func TestMissingBackendMutationIsAudited(t *testing.T) {
	hook := captureAudit(t)
	response := perform(testRouter(nil), http.MethodPatch, "/activation", `{"enabled":true}`, `"7"`)
	if response.Code != http.StatusServiceUnavailable || len(hook.AllEntries()) != 1 || hook.LastEntry().Data["action"] != Activate {
		t.Fatal("unavailable backend was not audited")
	}
}
