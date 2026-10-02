package models

import (
	"strings"
)

func applyCodexClientDevinDisplayName(entry map[string]any, id string, model map[string]any, providersForModel ProvidersForModelFunc, lookup modelInfoLookupFunc) {
	if !isCodexClientDevinModel(id, model, entry, providersForModel, lookup) {
		return
	}
	displayName := stringModelValue(entry, "display_name")
	if displayName == "" {
		displayName = id
	}
	trimmed := strings.TrimSpace(displayName)
	if strings.HasSuffix(trimmed, " (Devin)") {
		return
	}
	if strings.HasSuffix(strings.ToLower(trimmed), " (devin)") {
		entry["display_name"] = trimmed[:len(trimmed)-len(" (devin)")] + " (Devin)"
		return
	}
	if strings.HasSuffix(strings.ToLower(trimmed), "(devin)") {
		entry["display_name"] = strings.TrimSpace(trimmed[:len(trimmed)-len("(devin)")]) + " (Devin)"
		return
	}
	entry["display_name"] = trimmed + " (Devin)"
}

func isCodexClientDevinModel(id string, model map[string]any, entry map[string]any, providersForModel ProvidersForModelFunc, lookup modelInfoLookupFunc) bool {
	if isCodexDevinRoute(id) {
		return true
	}
	if entry != nil {
		if isCodexDevinRoute(stringModelValue(entry, "slug")) {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(stringModelValue(entry, "type")), "devin") {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(stringModelValue(entry, "owned_by")), "cognition") {
			return true
		}
	}
	if model != nil {
		if strings.EqualFold(strings.TrimSpace(stringModelValue(model, "type")), "devin") {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(stringModelValue(model, "owned_by")), "cognition") {
			return true
		}
	}
	if info := lookup(id); info != nil {
		if strings.EqualFold(info.Type, "devin") || strings.EqualFold(info.OwnedBy, "cognition") || strings.HasPrefix(strings.ToLower(info.ID), "devin/") {
			return true
		}
	} else if idx := strings.Index(id, "/"); idx != -1 {
		base := strings.TrimSpace(id[idx+1:])
		if info := lookup(base); info != nil {
			if strings.EqualFold(info.Type, "devin") || strings.EqualFold(info.OwnedBy, "cognition") || strings.HasPrefix(strings.ToLower(info.ID), "devin/") {
				return true
			}
		}
	}
	if providersForModel != nil {
		providers := providersForModel(id)
		if len(providers) == 0 && strings.Contains(id, "/") {
			idx := strings.Index(id, "/")
			base := strings.TrimSpace(id[idx+1:])
			providers = providersForModel(base)
		}
		for _, p := range providers {
			if strings.EqualFold(strings.TrimSpace(p), "devin") {
				return true
			}
		}
	}
	return false
}

func isCodexDevinRoute(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	if strings.HasPrefix(id, "devin/") {
		return true
	}
	if idx := strings.Index(id, "/"); idx != -1 {
		return strings.HasPrefix(id[idx+1:], "devin/")
	}
	return false
}
