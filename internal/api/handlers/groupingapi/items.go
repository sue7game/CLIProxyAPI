package groupingapi

import (
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func (a *adapter) items(kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		query, ok := parseItemQuery(c.Request.URL.RawQuery)
		if !ok || query.mode == filterAccessible && kind != KindCredential {
			invalid(c, "Use filter_mode=actual|accessible, a valid group_id, limit=1..500, and offset with limit; accessible requires group_id and is only valid for credentials.")
			return
		}
		result, err := a.backend.Items(c.Request.Context(), kind)
		if err != nil {
			backendError(c, err)
			return
		}
		if c.Request.URL.RawQuery != "" {
			result, err = query.apply(result)
			if err != nil {
				backendError(c, err)
				return
			}
		}
		if result.Items == nil {
			result.Items = []Item{}
		}
		respond(c, result.Revision, result)
	}
}

func (query itemQuery) apply(result ItemsResult) (ItemsResult, error) {
	var rules *grouping.Rules
	if query.mode == filterAccessible {
		var err error
		rules, err = grouping.NewRules(result.GroupIDs)
		if err != nil || result.GroupIDs == nil {
			return ItemsResult{}, ErrUnavailable
		}
	}
	items := make([]Item, 0, len(result.Items))
	for _, item := range result.Items {
		if query.matches(item, rules) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	result.Items, result.Pagination = items, nil
	if query.limit != 0 {
		result.Pagination = &ItemsPagination{Total: len(items), Offset: query.offset, Limit: query.limit}
		start := min(query.offset, len(items))
		end := start + min(query.limit, len(items)-start)
		result.Items = items[start:end]
	}
	return result, nil
}

func (query itemQuery) matches(item Item, rules *grouping.Rules) bool {
	if query.mode != filterAccessible {
		return query.groupID == "" || item.GroupID == query.groupID
	}
	token := grouping.Binding{ID: "group-filter", Kind: grouping.Token, GroupID: query.groupID, State: grouping.Active}
	credential := grouping.Binding{ID: item.ID, Kind: grouping.ObjectKind(item.Kind),
		GroupID: item.GroupID, State: grouping.RegistrationState(item.State)}
	return rules.Allows(token, credential)
}
