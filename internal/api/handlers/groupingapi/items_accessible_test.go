package groupingapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

const otherQueryGroup = "3914e6a7-0a1f-4808-956a-177db5eb8f04"

func accessibleBackend() *itemBackend {
	return &itemBackend{fakeBackend: newBackend(), groupIDs: []string{queryGroup, otherQueryGroup},
		items: []Item{
			{ID: "c", Kind: KindCredential, GroupID: queryGroup, State: "active"},
			{ID: "b", Kind: KindCredential, GroupID: "all", State: "active"},
			{ID: "a", Kind: KindCredential, GroupID: otherQueryGroup, State: "active"},
			{ID: "pending", Kind: KindCredential, GroupID: queryGroup, State: "pending_rebind"},
			{ID: "retired", Kind: KindCredential, GroupID: "all", State: "tombstone"},
			{ID: "token", Kind: KindToken, GroupID: queryGroup, State: "active"},
		}}
}

func TestAccessibleCredentialFilterUsesPolicyAndOneSnapshot(t *testing.T) {
	tests := []struct {
		group string
		ids   []string
	}{
		{"all", []string{"a", "b", "c"}},
		{queryGroup, []string{"b", "c"}},
		{otherQueryGroup, []string{"a", "b"}},
		{"74a14f38-d1cd-4c20-8047-8f6dcc383edd", []string{}},
	}
	for _, test := range tests {
		t.Run(test.group, func(t *testing.T) {
			backend := accessibleBackend()
			response := perform(testRouter(backend), http.MethodGet,
				"/credentials?filter_mode=accessible&group_id="+test.group, "", "")
			var result ItemsResult
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
				t.Fatalf("filter failed: %d %s", response.Code, response.Body)
			}
			ids := make([]string, 0, len(result.Items))
			for _, item := range result.Items {
				ids = append(ids, item.ID)
			}
			if !reflect.DeepEqual(ids, test.ids) || result.Revision != 7 || backend.calls != 1 {
				t.Fatalf("incorrect accessible filter: %+v calls=%d", result, backend.calls)
			}
			if result.GroupIDs != nil {
				t.Fatal("internal group catalog must not be serialized")
			}
		})
	}
}

func TestAccessiblePaginationCountsFilteredActiveCredentials(t *testing.T) {
	backend := accessibleBackend()
	response := perform(testRouter(backend), http.MethodGet,
		"/credentials?filter_mode=accessible&group_id="+queryGroup+"&limit=1&offset=1", "", "")
	var result ItemsResult
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatalf("page failed: %d %s", response.Code, response.Body)
	}
	if len(result.Items) != 1 || result.Items[0].ID != "c" ||
		!reflect.DeepEqual(result.Pagination, &ItemsPagination{Total: 2, Offset: 1, Limit: 1}) {
		t.Fatalf("incorrect accessible page: %+v", result)
	}
}

func TestTokensRejectAccessibleModeBeforeBackend(t *testing.T) {
	for _, group := range []string{"all", queryGroup} {
		backend := newBackend()
		response := perform(testRouter(backend), http.MethodGet,
			"/tokens?filter_mode=accessible&group_id="+group, "", "")
		if response.Code != http.StatusBadRequest || backend.calls != 0 {
			t.Fatal("tokens accepted accessible mode")
		}
	}
}

func TestAccessibleFilterFailsClosedWithoutTrustedGroupCatalog(t *testing.T) {
	for _, groups := range [][]string{nil, {queryGroup, queryGroup}, {"all"}} {
		backend := accessibleBackend()
		backend.groupIDs = groups
		response := perform(testRouter(backend), http.MethodGet,
			"/credentials?filter_mode=accessible&group_id=all", "", "")
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("untrusted group catalog accepted: %d", response.Code)
		}
	}
}
