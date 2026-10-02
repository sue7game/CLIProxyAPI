package groupingapi

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const (
	filterActual     = "actual"
	filterAccessible = "accessible"
)

type itemQuery struct {
	groupID string
	mode    string
	offset  int
	limit   int
}

func parseItemQuery(raw string) (itemQuery, bool) {
	query := itemQuery{mode: filterActual}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return query, false
	}
	if raw != "" && (strings.HasPrefix(raw, "&") || strings.HasSuffix(raw, "&") || strings.Contains(raw, "&&")) {
		return query, false
	}
	for key, values := range values {
		if len(values) != 1 || values[0] == "" || !query.set(key, values[0]) {
			return query, false
		}
	}
	if query.mode == filterAccessible && query.groupID == "" {
		return query, false
	}
	return query, !values.Has("offset") || values.Has("limit")
}

func (query *itemQuery) set(key, value string) bool {
	switch key {
	case "group_id":
		query.groupID = value
		return value == "all" || canonicalUUID(value)
	case "filter_mode":
		query.mode = value
		return value == filterActual || value == filterAccessible
	case "offset", "limit":
		number, err := strconv.Atoi(value)
		if err != nil || number < 0 || strconv.Itoa(number) != value {
			return false
		}
		if key == "offset" {
			query.offset = number
			return true
		}
		query.limit = number
		return number > 0 && number <= 500
	default:
		return false
	}
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
