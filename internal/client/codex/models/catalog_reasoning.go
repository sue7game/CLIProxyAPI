package models

import (
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

var codexClientAllowedReasoningLevels = map[string]struct{}{
	"none":    {},
	"minimal": {},
	"low":     {},
	"medium":  {},
	"high":    {},
	"xhigh":   {},
	"max":     {},
	"ultra":   {},
}

var codexClientLegacyAllowedReasoningLevels = map[string]struct{}{
	"none":    {},
	"minimal": {},
	"low":     {},
	"medium":  {},
	"high":    {},
	"xhigh":   {},
}

func applyCodexClientThinkingMetadata(entry map[string]any, thinking *registry.ThinkingSupport, clientVersion string) {
	if thinking == nil {
		return
	}

	levels := make([]any, 0, len(thinking.Levels))
	defaultLevel := ""
	firstLevel := ""
	for _, rawLevel := range thinking.Levels {
		level := normalizeCodexClientReasoningLevel(rawLevel, clientVersion)
		if level == "" {
			continue
		}
		if firstLevel == "" {
			firstLevel = level
		}
		if (defaultLevel == "" && level != "none") || level == "medium" {
			defaultLevel = level
		}
		levels = append(levels, map[string]any{
			"effort":      level,
			"description": codexClientReasoningDescription(level),
		})
	}
	if len(levels) == 0 {
		entry["supported_reasoning_levels"] = levels
		delete(entry, "default_reasoning_level")
		return
	}
	if defaultLevel == "" {
		defaultLevel = firstLevel
	}

	entry["supported_reasoning_levels"] = levels
	entry["default_reasoning_level"] = defaultLevel
}

func sanitizeCodexClientReasoningMetadata(entry map[string]any, clientVersion string) {
	rawLevels, ok := entry["supported_reasoning_levels"].([]any)
	if !ok {
		return
	}

	levels := make([]any, 0, len(rawLevels))
	allowedDefaults := make(map[string]struct{}, len(rawLevels))
	for _, rawLevelEntry := range rawLevels {
		levelEntry, ok := rawLevelEntry.(map[string]any)
		if !ok {
			continue
		}
		level := normalizeCodexClientReasoningLevel(stringModelValue(levelEntry, "effort"), clientVersion)
		if level == "" {
			continue
		}
		clonedEntry := cloneCodexClientModelMap(levelEntry)
		clonedEntry["effort"] = level
		levels = append(levels, clonedEntry)
		allowedDefaults[level] = struct{}{}
	}

	if len(levels) == 0 {
		entry["supported_reasoning_levels"] = levels
		delete(entry, "default_reasoning_level")
		return
	}

	defaultLevel := normalizeCodexClientReasoningLevel(stringModelValue(entry, "default_reasoning_level"), clientVersion)
	if _, ok := allowedDefaults[defaultLevel]; !ok {
		defaultLevel = stringModelValue(levels[0].(map[string]any), "effort")
	}

	entry["supported_reasoning_levels"] = levels
	entry["default_reasoning_level"] = defaultLevel
}

func normalizeCodexClientReasoningLevel(rawLevel string, clientVersion string) string {
	level := strings.ToLower(strings.TrimSpace(rawLevel))
	if !supportsExtendedReasoningLevels(clientVersion) {
		if _, ok := codexClientLegacyAllowedReasoningLevels[level]; !ok {
			return ""
		}
		return level
	}
	if _, ok := codexClientAllowedReasoningLevels[level]; !ok {
		return ""
	}
	return level
}

// supportsExtendedReasoningLevels reports whether the given clientVersion supports
// extended reasoning effort levels ("max" and "ultra"), which require Codex CLI >= 0.144.0.
// If the version is empty or unparseable, it returns true to preserve modern features.
func supportsExtendedReasoningLevels(clientVersion string) bool {
	clientVersion = strings.TrimSpace(clientVersion)
	if clientVersion == "" {
		return true
	}
	cmp, ok := compareDottedVersions(clientVersion, "0.144.0")
	if !ok {
		return true
	}
	return cmp >= 0
}

func parseDottedVersion(version string) []int64 {
	version = strings.TrimSpace(version)
	if strings.HasPrefix(version, "v") || strings.HasPrefix(version, "V") {
		version = version[1:]
	}
	if idx := strings.IndexAny(version, "-+"); idx != -1 {
		version = version[:idx]
	}
	parts := strings.Split(version, ".")
	nums := make([]int64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		num, errParse := strconv.ParseInt(part, 10, 64)
		if errParse != nil || num < 0 {
			return nil
		}
		nums = append(nums, num)
	}
	return nums
}

func compareDottedVersions(a, b string) (int, bool) {
	numsA := parseDottedVersion(a)
	numsB := parseDottedVersion(b)
	if len(numsA) == 0 || len(numsB) == 0 {
		return 0, false
	}
	maxLen := len(numsA)
	if len(numsB) > maxLen {
		maxLen = len(numsB)
	}
	for i := 0; i < maxLen; i++ {
		var valA, valB int64
		if i < len(numsA) {
			valA = numsA[i]
		}
		if i < len(numsB) {
			valB = numsB[i]
		}
		if valA < valB {
			return -1, true
		}
		if valA > valB {
			return 1, true
		}
	}
	return 0, true
}

func codexClientReasoningDescription(level string) string {
	switch level {
	case "none":
		return "No reasoning"
	case "minimal":
		return "Fastest responses with minimal reasoning"
	case "low":
		return "Fast responses with lighter reasoning"
	case "medium":
		return "Balances speed and reasoning depth for everyday tasks"
	case "high":
		return "Greater reasoning depth for complex problems"
	case "xhigh":
		return "Extra high reasoning depth for complex problems"
	case "max":
		return "Maximum available reasoning depth for complex problems"
	default:
		return level
	}
}
