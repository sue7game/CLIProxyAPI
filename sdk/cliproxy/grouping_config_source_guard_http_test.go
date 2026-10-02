package cliproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestGroupingV8RejectsUnacceptedSourceChanges(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, canonical := range []bool{false, true} {
			for _, change := range []string{"credential", "token"} {
				name := fmt.Sprintf("enabled=%t/canonical=%t/%s", enabled, canonical, change)
				t.Run(name, func(t *testing.T) {
					verifyGroupingV8UnacceptedSourceChange(t, enabled, canonical, change)
				})
			}
		}
	}
}

func verifyGroupingV8UnacceptedSourceChange(t *testing.T, enabled, canonical bool, change string) {
	t.Helper()
	f := newGroupingSourceGuardFixture(t, enabled, canonical)
	before, current := f.snapshot(t), f.service.cfg.CloneForRuntime()
	original := readGroupingSourceGuardFile(t, f.path)
	external := mutateGroupingSourceGuardDocument(t, original, change)
	writeGroupingSourceGuardFile(t, f.path, external)
	etag := f.managed(t, http.MethodGet, "/config", nil, 0).Header().Get("ETag")
	if etag == "" {
		t.Fatal("fresh disk snapshot has no ETag")
	}
	response := f.request(t, http.MethodPatch, "/v8/management/config/observability/logs/debug", true, 0,
		groupingHTTPManagementKey, map[string]string{"If-Match": etag})
	var problem struct {
		Error string `json:"error"`
	}
	if response.Code != http.StatusConflict || json.Unmarshal(response.Body.Bytes(), &problem) != nil || problem.Error != "grouping_source_changed" {
		t.Fatalf("unaccepted %s change was not rejected: %d %s", change, response.Code, response.Body.String())
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) || !reflect.DeepEqual(current, f.service.cfg) || !reflect.DeepEqual(current, f.service.grouping.current.Load()) {
		t.Fatal("rejected mutation changed policy or accepted runtime configuration")
	}
	if !bytes.Equal(external, readGroupingSourceGuardFile(t, f.path)) {
		t.Fatal("rejected mutation overwrote external source bytes")
	}
	assertGroupingSourceGuardHealthy(t, f)
	writeGroupingSourceGuardFile(t, f.path, original)
	f.managed(t, http.MethodPatch, "/config/observability/logs/debug", true, 0)
	if !f.service.cfg.Debug || !reflect.DeepEqual(before.Identities, f.snapshot(t).Identities) {
		t.Fatal("retry after source restoration changed identities or failed to publish configuration")
	}
	assertGroupingSourceGuardHealthy(t, f)
}

func TestGroupingV8AcceptedExternalSourcesRemainPending(t *testing.T) {
	for _, canonical := range []bool{false, true} {
		for _, change := range []string{"credential", "token"} {
			t.Run(fmt.Sprintf("canonical=%t/%s", canonical, change), func(t *testing.T) {
				verifyGroupingV8PendingSourceChange(t, canonical, change)
			})
		}
	}
}

func verifyGroupingV8PendingSourceChange(t *testing.T, canonical bool, change string) {
	t.Helper()
	f := newGroupingSourceGuardFixture(t, true, canonical)
	before := f.snapshot(t)
	id := f.service.cfg.CodexKey[0].GroupingID
	external := mutateGroupingSourceGuardDocument(t, readGroupingSourceGuardFile(t, f.path), change)
	writeGroupingSourceGuardFile(t, f.path, external)
	loaded, err := config.LoadConfig(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if !f.service.applyConfigUpdateWithAuthSynthesis(f.ctx, loaded, true) {
		t.Fatal("watcher-style reconciliation failed")
	}
	pending := f.snapshot(t)
	if change == "token" {
		id = ""
		for candidate, identity := range pending.Identities {
			if _, existed := before.Identities[candidate]; !existed && identity.Kind == grouping.Token {
				id = candidate
			}
		}
	}
	if id == "" || pending.Identities[id].State != grouping.PendingRebind {
		t.Fatal("external source was not marked pending during reconciliation")
	}
	f.managed(t, http.MethodPatch, "/config/observability/logs/debug", true, 0)
	if !reflect.DeepEqual(pending.Identities, f.snapshot(t).Identities) || !f.service.cfg.Debug {
		t.Fatal("unrelated mutation approved a pending source or failed to publish configuration")
	}
	assertGroupingPendingSourceDenied(t, f, change, id)
	assertGroupingSourceGuardHealthy(t, f)
}

func assertGroupingPendingSourceDenied(t *testing.T, f *groupingHTTPFixture, change, id string) {
	t.Helper()
	if change == "credential" {
		for _, auth := range f.service.coreManager.List() {
			if auth.Attributes["grouping_id"] == id {
				if f.service.coreManager.AuthorizeCredentialUse(f.principal(), auth) == nil {
					t.Fatal("pending replacement credential was authorized")
				}
				return
			}
		}
		t.Fatal("pending replacement credential was not published")
	}
	f.installTestExecutor(t)
	response := f.request(t, http.MethodPost, "/v1/chat/completions", gin.H{
		"model": groupingHTTPModel, "messages": []gin.H{{"role": "user", "content": "local fixture"}},
	}, 0, groupingSourceGuardExternalToken)
	if response.Code != http.StatusUnauthorized || f.executor.calls.Load() != 0 {
		t.Fatalf("pending external token reached authorization or execution: %d %s", response.Code, response.Body.String())
	}
}

func TestGroupingV8ManagedReplacementStillRetainsBinding(t *testing.T) {
	f := newGroupingSourceGuardFixture(t, true, true)
	keys := f.service.cfg.CloneForRuntime().CodexKey
	id := keys[0].GroupingID
	group := f.createHTTPGroup(t, "managed replacement")
	f.managed(t, http.MethodPatch, "/grouping/bindings", groupingapi.BindingRequest{
		CredentialIDs: []string{id}, GroupID: group, ConfirmPermissionExpansion: true,
	}, f.snapshot(t).Revision)
	before := f.snapshot(t).Identities
	keys[0].APIKey = "managed-replacement-fixture"
	f.managed(t, http.MethodPut, "/config/api-keys/codex", groupingV8CodexPayload(keys), 0)
	after := f.snapshot(t).Identities
	if after[id].State != grouping.Active || after[id].GroupID != group || after[id].Fingerprint == before[id].Fingerprint {
		t.Fatal("managed replacement was rejected or lost its binding")
	}
	for otherID, identity := range before {
		if otherID != id && identity != after[otherID] {
			t.Fatal("managed replacement changed an independent identity")
		}
	}
	assertGroupingSourceGuardHealthy(t, f)
}
