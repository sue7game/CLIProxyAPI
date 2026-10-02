package groupingadmin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
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

func TestBindingAuditCoversFailedAndSuccessfulAttempts(t *testing.T) {
	hook := captureAudit(t)
	f := newFixture(t, sourceRecord{"token", grouping.Token, "A", grouping.Active})
	request := groupingapi.BindingRequest{TokenIDs: []string{f.ids["token"]}, GroupID: "all"}
	_, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Bind, Binding: request})
	if !errors.Is(err, groupingapi.ErrConflict) {
		t.Fatal("unconfirmed wildcard move succeeded")
	}
	assertAudit(t, hook.LastEntry(), groupingapi.Bind, 1, false)
	if hook.LastEntry().Data["confirmation_reason"] != nil {
		t.Fatal("audit invented explicit confirmation")
	}
	request.ConfirmPermissionExpansion = true
	_, err = f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Bind, Binding: request})
	if err != nil {
		t.Fatal(err)
	}
	entry := hook.LastEntry()
	assertAudit(t, entry, groupingapi.Bind, 2, true)
	want := []groupingapi.AuditGroupChange{{ID: f.ids["token"], OldGroup: f.groups["A"], NewGroup: "all"}}
	if entry.Data["namespace"] != snapshotOf(t, f).Namespace || !reflect.DeepEqual(entry.Data["group_changes"], want) ||
		entry.Data["confirmation_reason"] != "permission_expansion" {
		t.Fatalf("incorrect binding audit: %+v", entry.Data)
	}
	_, err = f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Bind, Binding: request})
	if !errors.Is(err, groupingapi.ErrPrecondition) || len(hook.AllEntries()) != 3 {
		t.Fatal("failed CAS was not audited exactly once")
	}
	assertAudit(t, hook.LastEntry(), groupingapi.Bind, 1, false)
	if hook.LastEntry().Data["group_changes"] != nil {
		t.Fatal("stale request was attributed relationships from a newer revision")
	}
}

func assertAudit(t *testing.T, entry *log.Entry, action groupingapi.Operation, revision uint64, success bool) {
	t.Helper()
	message, level := "grouping management mutation failed", log.WarnLevel
	if success {
		message, level = "grouping management mutation succeeded", log.InfoLevel
	}
	if entry == nil || entry.Message != message || entry.Level != level || entry.Data["action"] != action || entry.Data["revision"] != revision {
		t.Fatalf("unexpected audit entry: %+v", entry)
	}
	allowed := map[string]bool{"action": true, "namespace": true, "revision": true, "logical_ids": true,
		"group_changes": true, "confirmation_reason": true}
	for key := range entry.Data {
		if !allowed[key] {
			t.Fatalf("unexpected audit field %s", key)
		}
	}
	data, err := json.Marshal(entry.Data)
	if err != nil || strings.Contains(string(data), "private-secret") || strings.Contains(string(data), strings.Repeat("a", 64)) {
		t.Fatalf("audit leaked source material: %s %v", data, err)
	}
}

func TestGroupAuditDoesNotIncludeDisplayNames(t *testing.T) {
	hook := captureAudit(t)
	f := newFixture(t)
	result, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: "private-secret"})
	if err != nil {
		t.Fatal(err)
	}
	assertAudit(t, hook.LastEntry(), groupingapi.CreateGroup, 2, true)
	if !reflect.DeepEqual(hook.LastEntry().Data["logical_ids"], []string{result.Group.ID}) {
		t.Fatal("created group UUID missing from audit")
	}
	for index, operation := range []groupingapi.Operation{groupingapi.RenameGroup, groupingapi.DeleteGroup} {
		_, err = f.backend.Apply(testContext(), uint64(index+2), groupingapi.Mutation{Operation: operation, ID: result.Group.ID, Name: "private-secret-renamed"})
		if err != nil {
			t.Fatal(err)
		}
		assertAudit(t, hook.LastEntry(), operation, uint64(index+3), true)
	}
}

func TestAuditRemainsBoundToCommittedSnapshotAfterNotification(t *testing.T) {
	hook := captureAudit(t)
	f := newFixture(t, sourceRecord{"token", grouping.Token, "A", grouping.Active})
	f.backend.options.OnPolicyChanged = func() {
		f.mutex.Lock()
		defer f.mutex.Unlock()
		_, err := f.store.Update(2, func(snapshot *grouping.Snapshot) error {
			return snapshot.Bind([]string{f.ids["token"]}, f.groups["C"])
		})
		if err != nil {
			t.Error(err)
		}
	}
	_, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Bind,
		Binding: groupingapi.BindingRequest{TokenIDs: []string{f.ids["token"]}, GroupID: f.groups["B"]}})
	if err != nil || snapshotOf(t, f).Revision != 3 {
		t.Fatalf("concurrent notification setup failed: %v", err)
	}
	assertAudit(t, hook.LastEntry(), groupingapi.Bind, 2, true)
	changes := hook.LastEntry().Data["group_changes"].([]groupingapi.AuditGroupChange)
	if len(changes) != 1 || changes[0].OldGroup != f.groups["A"] || changes[0].NewGroup != f.groups["B"] {
		t.Fatal("audit reread later state instead of the atomic mutation snapshot")
	}
}

func TestHTTPDelegationDoesNotDuplicateAudit(t *testing.T) {
	hook := captureAudit(t)
	f := newFixture(t, sourceRecord{"token", grouping.Token, "A", grouping.Active})
	router := gin.New()
	groupingapi.Register(router.Group("/v0/management"), f.backend)
	request := groupingapi.BindingRequest{TokenIDs: []string{f.ids["token"]}, GroupID: "all"}
	if result := requestBinding(t, router, request, `"1"`); result.Code != http.StatusConflict {
		t.Fatal("unconfirmed binding should fail")
	}
	request.ConfirmPermissionExpansion = true
	if result := requestBinding(t, router, request, `"1"`); result.Code != http.StatusOK {
		t.Fatal("confirmed binding should succeed")
	}
	if len(hook.AllEntries()) != 2 {
		t.Fatal("backend audit was duplicated by HTTP adapter")
	}
}

func TestLifecycleFailuresDoNotLogCallbackErrors(t *testing.T) {
	hook := captureAudit(t)
	f := newFixture(t, sourceRecord{"pending", grouping.Credential, "A", grouping.PendingRebind})
	f.backend.options.Rebind = func(context.Context, uint64, groupingapi.Mutation) (groupingapi.ApplyResult, error) {
		return groupingapi.ApplyResult{}, errors.New("private-secret fingerprint")
	}
	_, err := f.backend.Apply(testContext(), 1, groupingapi.Mutation{Operation: groupingapi.Rebind, ID: f.ids["pending"], Confirm: true})
	if !errors.Is(err, groupingapi.ErrUnavailable) {
		t.Fatal(err)
	}
	assertAudit(t, hook.LastEntry(), groupingapi.Rebind, 1, false)
	if hook.LastEntry().Data["confirmation_reason"] != "identity_rebind" {
		t.Fatal("rebind confirmation reason missing")
	}
	_, err = f.backend.Initialize(testContext())
	if !errors.Is(err, groupingapi.ErrUnavailable) {
		t.Fatal(err)
	}
	assertAudit(t, hook.LastEntry(), "initialize", 0, false)
}
