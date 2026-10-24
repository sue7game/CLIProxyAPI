package handlers

import (
	"encoding/json"
	"errors"
)

// restrictModelListResponse prevents response plugins from widening a scoped catalog.
func restrictModelListResponse(original, intercepted []byte) ([]byte, error) {
	var before, after map[string]json.RawMessage
	if json.Unmarshal(original, &before) != nil || json.Unmarshal(intercepted, &after) != nil {
		return nil, errors.New("invalid scoped model catalog")
	}
	key := "data"
	if _, ok := before[key]; !ok {
		key = "models"
	}
	originalItems, err := catalogItems(before, key)
	if err != nil {
		return nil, err
	}
	items, err := catalogItems(after, key)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(originalItems))
	for _, item := range originalItems {
		allowed[catalogItemID(item)] = true
	}
	filtered := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		id := catalogItemID(item)
		if id != "" && allowed[id] {
			filtered = append(filtered, item)
		}
	}
	encoded, err := json.Marshal(filtered)
	if err != nil {
		return nil, err
	}
	after[key] = encoded
	repairCatalogPagination(after, filtered)
	return json.Marshal(after)
}

func catalogItems(body map[string]json.RawMessage, key string) ([]json.RawMessage, error) {
	raw, exists := body[key]
	if !exists {
		return nil, errors.New("missing scoped model catalog")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, errors.New("invalid scoped model catalog entries")
	}
	return items, nil
}

func catalogItemID(raw json.RawMessage) string {
	var item map[string]json.RawMessage
	if json.Unmarshal(raw, &item) != nil {
		return ""
	}
	for _, key := range []string{"id", "name", "slug"} {
		var id string
		if json.Unmarshal(item[key], &id) == nil && id != "" {
			return key + ":" + id
		}
	}
	return ""
}

func repairCatalogPagination(body map[string]json.RawMessage, items []json.RawMessage) {
	for _, key := range []string{"first_id", "last_id"} {
		if _, exists := body[key]; !exists {
			continue
		}
		value := json.RawMessage(`""`)
		if len(items) != 0 {
			index := 0
			if key == "last_id" {
				index = len(items) - 1
			}
			var item map[string]json.RawMessage
			if json.Unmarshal(items[index], &item) == nil && item["id"] != nil {
				value = item["id"]
			}
		}
		body[key] = value
	}
	if _, exists := body["has_more"]; exists {
		body["has_more"] = json.RawMessage("false")
	}
	delete(body, "nextPageToken")
}
