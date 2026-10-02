package groupingadmin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestRealBackendAccessibleFilterIncludesAllCredentials(t *testing.T) {
	f := newFixture(t, sourceRecord{"a", grouping.Credential, "A", grouping.Active},
		sourceRecord{"b", grouping.Credential, "B", grouping.Active},
		sourceRecord{"all", grouping.Credential, "all", grouping.Active},
		sourceRecord{"pending", grouping.Credential, "A", grouping.PendingRebind},
		sourceRecord{"retired", grouping.Credential, "all", grouping.Tombstone})
	router := gin.New()
	groupingapi.Register(router.Group("/v0/management"), f.backend)
	for _, group := range []string{f.groups["A"], "all", f.groups["C"]} {
		request := httptest.NewRequest(http.MethodGet, "/v0/management/grouping/credentials?filter_mode=accessible&group_id="+group, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		var result groupingapi.ItemsResult
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
			t.Fatalf("accessible filter failed: %d %s", response.Code, response.Body)
		}
		want := []string{f.ids["all"]}
		if group == f.groups["A"] || group == "all" {
			want = append(want, f.ids["a"])
		}
		if group == "all" {
			want = append(want, f.ids["b"])
		}
		sort.Strings(want)
		ids := make([]string, 0, len(result.Items))
		for _, item := range result.Items {
			ids = append(ids, item.ID)
		}
		if !reflect.DeepEqual(ids, want) || result.Revision != 1 || response.Header().Get("ETag") != `"1"` {
			t.Fatalf("incorrect accessible snapshot: %+v", result)
		}
	}
}
