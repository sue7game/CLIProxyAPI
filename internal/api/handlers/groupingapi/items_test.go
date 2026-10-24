package groupingapi

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"testing"
)

const queryGroup = "fe969cbb-f2d5-42c4-9542-2c4a63c098f5"

type itemBackend struct {
	*fakeBackend
	items    []Item
	groupIDs []string
}

func (b *itemBackend) Items(ctx context.Context, kind string) (ItemsResult, error) {
	result, err := b.fakeBackend.Items(ctx, kind)
	result.Items = b.items
	result.GroupIDs = b.groupIDs
	return result, err
}

func TestItemQueryRejectsAmbiguousParameters(t *testing.T) {
	queries := []string{
		"group_id=", "group_id=*", "group_id=ALL", "group_id=%20all", "group_id=all%20",
		"group_id=all&group_id=all", "group_id=all&%67roup_id=all", "group_id=missing",
		"group_id=00000000-0000-0000-0000-000000000000", "group_id=FE969CBB-F2D5-42C4-9542-2C4A63C098F5",
		"group=all", "mode=accessible", "page=1", "unknown=secret", "offset=0", "offset=1",
		"limit=", "limit=0", "limit=501", "limit=-1", "limit=%2B1", "limit=01", "limit=1.0",
		"limit=1&limit=2", "limit=1&offset=00", "limit=1&offset=-1", "limit=1&offset=1&offset=2",
		"limit=999999999999999999999999", "limit=1&offset=999999999999999999999999",
		"limit=%ZZ", "group_id=all;limit=1", "limit=1&&offset=0", "&", "limit=1&",
		"filter_mode=", "filter_mode=all", "filter_mode=Actual", "filter_mode=accessible",
		"filter_mode=actual&filter_mode=accessible&group_id=all", "filter_mode=%20actual",
	}
	for _, path := range []string{"/tokens", "/credentials"} {
		for _, query := range queries {
			t.Run(path+"?"+query, func(t *testing.T) {
				backend := newBackend()
				result := perform(testRouter(backend), http.MethodGet, path+"?"+query, "", "")
				if result.Code != http.StatusBadRequest || backend.calls != 0 {
					t.Fatalf("invalid query reached backend: status=%d calls=%d", result.Code, backend.calls)
				}
			})
		}
	}
}

func TestItemQueryUsesExactMembershipAndStablePages(t *testing.T) {
	tests := []struct {
		query string
		ids   []string
		page  *ItemsPagination
	}{
		{"", []string{"c", "b", "a"}, nil},
		{"?group_id=all", []string{"b"}, nil},
		{"?filter_mode=actual&group_id=all", []string{"b"}, nil},
		{"?group_id=" + queryGroup, []string{"a", "c"}, nil},
		{"?group_id=3914e6a7-0a1f-4808-956a-177db5eb8f04", []string{}, nil},
		{"?limit=2", []string{"a", "b"}, &ItemsPagination{Total: 3, Limit: 2}},
		{"?group_id=" + queryGroup + "&limit=1&offset=1", []string{"c"}, &ItemsPagination{Total: 2, Offset: 1, Limit: 1}},
		{"?limit=1&offset=3", []string{}, &ItemsPagination{Total: 3, Offset: 3, Limit: 1}},
		{"?limit=500&offset=" + strconv.Itoa(int(^uint(0)>>1)), []string{},
			&ItemsPagination{Total: 3, Offset: int(^uint(0) >> 1), Limit: 500}},
	}
	for _, path := range []string{"/tokens", "/credentials"} {
		for _, test := range tests {
			t.Run(path+test.query, func(t *testing.T) {
				backend := &itemBackend{fakeBackend: newBackend(), items: []Item{
					{ID: "c", GroupID: queryGroup, State: "pending_rebind"},
					{ID: "b", GroupID: "all", State: "active"}, {ID: "a", GroupID: queryGroup, State: "tombstone"},
				}}
				original := append([]Item(nil), backend.items...)
				response := perform(testRouter(backend), http.MethodGet, path+test.query, "", "")
				var result ItemsResult
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
					t.Fatalf("query failed: %d %s", response.Code, response.Body)
				}
				ids := make([]string, 0, len(result.Items))
				for _, item := range result.Items {
					ids = append(ids, item.ID)
				}
				if !reflect.DeepEqual(ids, test.ids) || !reflect.DeepEqual(result.Pagination, test.page) {
					t.Fatalf("unexpected page: %+v", result)
				}
				if result.Revision != 7 || response.Header().Get("ETag") != `"7"` || backend.calls != 1 {
					t.Fatal("page and metadata must come from a single revisioned read")
				}
				if !reflect.DeepEqual(original, backend.items) {
					t.Fatal("pagination mutated backend-owned data")
				}
			})
		}
	}
}

func TestEmptyPagesRetainArraysAndLegacyShape(t *testing.T) {
	for query, want := range map[string]string{
		"":              `{"revision":7,"items":[]}`,
		"?group_id=all": `{"revision":7,"items":[]}`,
		"?limit=10":     `{"revision":7,"items":[],"pagination":{"total":0,"offset":0,"limit":10}}`,
	} {
		result := perform(testRouter(newBackend()), http.MethodGet, "/credentials"+query, "", "")
		if result.Body.String() != want {
			t.Fatalf("unexpected response: %s", result.Body)
		}
	}
}
