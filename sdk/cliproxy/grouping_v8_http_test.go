package cliproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

func TestGroupingV8ConfigMigrationRetainsBindingsAndAuthorization(t *testing.T) {
	f := newGroupingHTTPFixture(t)
	f.managed(t, http.MethodPost, "/grouping/initialize", gin.H{}, 0)
	team := f.createHTTPGroup(t, "v8 migration")
	var tokens, credentials []string
	for id, identity := range f.snapshot(t).Identities {
		if identity.Kind == grouping.Token {
			tokens = append(tokens, id)
		} else {
			credentials = append(credentials, id)
		}
	}
	f.managed(t, http.MethodPatch, "/grouping/bindings", groupingapi.BindingRequest{
		TokenIDs: tokens, CredentialIDs: credentials, GroupID: team, ConfirmPermissionExpansion: true,
	}, f.snapshot(t).Revision)
	f.managed(t, http.MethodPatch, "/grouping/activation", gin.H{"enabled": true}, f.snapshot(t).Revision)
	before := f.snapshot(t)
	f.managed(t, http.MethodPatch, "/config/observability/logs/debug", true, 0)
	if !f.service.cfg.Debug || !reflect.DeepEqual(before.Identities, f.snapshot(t).Identities) {
		t.Fatal("v8 migration changed bindings or did not synchronously publish config")
	}
	assertV8ConfigPersisted(t, f)
	f.installTestExecutor(t)
	assertGroupingHTTPRequest(t, f, true)
}

func assertV8ConfigPersisted(t *testing.T, f *groupingHTTPFixture) {
	t.Helper()
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	if root["config-version"] != 8 || root["codex-api-key"] != nil {
		t.Fatal("v8 edit did not persist canonical layout")
	}
	groups := root["api-keys"].(map[string]any)["codex"].([]any)
	if len(groups) != 2 {
		t.Fatal("canonical migration lost duplicate sources")
	}
	for _, group := range groups {
		key := group.(map[string]any)["keys"].([]any)[0].(map[string]any)
		id, _ := key["grouping-id"].(string)
		if f.snapshot(t).Identities[id].State != grouping.Active {
			t.Fatal("canonical source UUID does not match active policy")
		}
	}
}

func TestGroupingV8ReorderAndDeleteRetainIndependentRecords(t *testing.T) {
	f := newGroupingHTTPFixture(t)
	f.managed(t, http.MethodPost, "/grouping/initialize", gin.H{}, 0)
	keys := f.service.cfg.CloneForRuntime().CodexKey
	firstID, secondID := keys[0].GroupingID, keys[1].GroupingID
	firstGroup := f.createHTTPGroup(t, "first duplicate")
	secondGroup := f.createHTTPGroup(t, "second duplicate")
	for _, binding := range []groupingapi.BindingRequest{
		{CredentialIDs: []string{firstID}, GroupID: firstGroup},
		{CredentialIDs: []string{secondID}, GroupID: secondGroup},
	} {
		binding.ConfirmPermissionExpansion = true
		f.managed(t, http.MethodPatch, "/grouping/bindings", binding, f.snapshot(t).Revision)
	}
	oldETag := f.managed(t, http.MethodGet, "/config", nil, 0).Header().Get("ETag")
	keys[0], keys[1] = keys[1], keys[0]
	f.managed(t, http.MethodPut, "/config/api-keys/codex", groupingV8CodexPayload(keys), 0)
	if f.service.cfg.CodexKey[0].GroupingID != secondID || f.snapshot(t).Identities[firstID].GroupID != firstGroup {
		t.Fatal("reorder moved a duplicate's binding")
	}
	deletion := groupingV8CodexPayload(keys[:1])
	assertGroupingV8ConfigPreconditions(t, f, deletion, oldETag)
	snapshot := f.snapshot(t)
	if snapshot.Identities[firstID].State != grouping.Tombstone || snapshot.Identities[secondID].State != grouping.Active || snapshot.Identities[secondID].GroupID != secondGroup {
		t.Fatal("deleting one duplicate modified the other record")
	}
}

func assertGroupingV8ConfigPreconditions(t *testing.T, f *groupingHTTPFixture, deletion []gin.H, oldETag string) {
	t.Helper()
	path := "/v8/management/config/api-keys/codex"
	before := f.snapshot(t)
	missing := f.request(t, http.MethodPut, path, deletion, 0, groupingHTTPManagementKey)
	if missing.Code != http.StatusPreconditionRequired {
		t.Fatalf("identity deletion without a snapshot: %d", missing.Code)
	}
	stale := f.request(t, http.MethodPut, path, deletion, 0, groupingHTTPManagementKey, map[string]string{"If-Match": oldETag})
	if stale.Code != http.StatusPreconditionFailed || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatalf("stale source deletion was accepted or changed policy: %d", stale.Code)
	}
	etag := f.managed(t, http.MethodGet, "/config", nil, 0).Header().Get("ETag")
	if etag == "" {
		t.Fatal("config snapshot has no ETag")
	}
	accepted := f.request(t, http.MethodPut, path, deletion, 0, groupingHTTPManagementKey, map[string]string{"If-Match": etag})
	if accepted.Code != http.StatusOK {
		t.Fatalf("current source deletion was rejected: %d %s", accepted.Code, accepted.Body.String())
	}
}

func TestGroupingV8RejectsIdentityLossWithoutMutatingPolicy(t *testing.T) {
	f := newGroupingHTTPFixture(t)
	f.managed(t, http.MethodPost, "/grouping/initialize", gin.H{}, 0)
	before := f.snapshot(t)
	keys := f.service.cfg.CloneForRuntime().CodexKey
	for index := range keys {
		keys[index].GroupingID = ""
	}
	response := f.request(t, http.MethodPut, "/v8/management/config/api-keys/codex", groupingV8CodexPayload(keys), 0, groupingHTTPManagementKey)
	if response.Code < 400 || !reflect.DeepEqual(before.Identities, f.snapshot(t).Identities) {
		t.Fatalf("missing IDs were accepted or policy changed: %d", response.Code)
	}
	var body map[string]any
	if json.Unmarshal(response.Body.Bytes(), &body) != nil {
		t.Fatal("rejected v8 mutation has no structured error")
	}
}

func groupingV8CodexPayload(keys []config.CodexKey) []gin.H {
	groups := make([]gin.H, len(keys))
	for index, key := range keys {
		item := gin.H{"api-key": key.APIKey}
		if key.GroupingID != "" {
			item["grouping-id"] = key.GroupingID
		}
		groups[index] = gin.H{"name": fmt.Sprintf("fixture-%d", index), "base-url": key.BaseURL, "keys": []gin.H{item}}
	}
	return groups
}
