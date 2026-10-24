package cliproxy

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func TestGroupingHTTPPreviewIncludesCredentialAndModelAccessWithoutUpstream(t *testing.T) {
	f := newGroupingHTTPFixture(t)
	f.managed(t, http.MethodPost, "/grouping/initialize", gin.H{}, 0)
	a, b := f.createHTTPGroup(t, "Preview A"), f.createHTTPGroup(t, "Preview B")
	var token string
	var credentials []string
	for id, identity := range f.snapshot(t).Identities {
		if identity.Kind == grouping.Token {
			token = id
		} else {
			credentials = append(credentials, id)
		}
	}
	f.bind(t, groupingapi.BindingRequest{TokenIDs: []string{token}, GroupID: a})
	f.bind(t, groupingapi.BindingRequest{CredentialIDs: credentials, GroupID: b})
	f.installTestExecutor(t)
	revision := f.snapshot(t).Revision
	response := f.managed(t, http.MethodPost, "/grouping/preview", groupingapi.BindingRequest{TokenIDs: []string{token}, GroupID: b}, 0)
	var preview groupingapi.PreviewResult
	if err := json.Unmarshal(response.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if !preview.ModelsAvailable || preview.Revision != revision || !preview.PermissionExpansion || preview.AffectedCount != 1 {
		t.Fatalf("invalid complete preview: %+v", preview)
	}
	if len(preview.CredentialAccessChanges) != 1 || preview.CredentialAccessChanges[0].AddedCount != len(credentials) {
		t.Fatalf("credential expansion missing: %+v", preview.CredentialAccessChanges)
	}
	if len(preview.ModelAccessChanges) != 1 || !reflect.DeepEqual(preview.ModelAccessChanges[0].Added, []string{groupingHTTPModel}) {
		t.Fatalf("registered model expansion missing: %+v", preview.ModelAccessChanges)
	}
	if f.snapshot(t).Revision != revision || f.executor.calls.Load() != 0 {
		t.Fatal("preview mutated policy or called upstream")
	}
}
