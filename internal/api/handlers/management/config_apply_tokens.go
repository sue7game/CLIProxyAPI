package management

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func validateAPIKeyTransition(previous, proposed []string, rotation *APIKeyRotation) error {
	before, after := make(map[string]bool), make(map[string]bool)
	for _, key := range previous {
		before[key] = true
	}
	for _, key := range proposed {
		if strings.TrimSpace(key) == "" || key != strings.TrimSpace(key) || after[key] {
			return &ConfigApplyError{400, "invalid_api_keys", "API tokens must be nonempty, distinct, and without surrounding whitespace"}
		}
		after[key] = true
	}
	added, removed := 0, 0
	for key := range after {
		if !before[key] {
			added++
		}
	}
	for key := range before {
		if !after[key] {
			removed++
		}
	}
	if rotation == nil {
		if added > 0 && removed > 0 {
			return &ConfigApplyError{409, "ambiguous_token_replacement", "replace an API token with PATCH old/new; bulk replacement cannot preserve its identity unambiguously"}
		}
		return nil
	}
	if rotation.Old == rotation.New && (added != 0 || removed != 0) {
		return &ConfigApplyError{409, "ambiguous_token_rotation", "a no-op rotation cannot include other token changes"}
	}
	if !before[rotation.Old] || !after[rotation.New] || rotation.Old != rotation.New && (after[rotation.Old] || before[rotation.New] || added != 1 || removed != 1) {
		return &ConfigApplyError{409, "ambiguous_token_rotation", "token rotation must replace exactly one existing token with a new distinct token"}
	}
	return nil
}

func (h *Handler) putAPIKeysWithConfigApply(c *gin.Context) bool {
	if !h.requiresConfigApplyRequest(c) {
		return false
	}
	data, err := c.GetRawData()
	var keys []string
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to read body"})
		return true
	}
	if err = json.Unmarshal(data, &keys); err != nil {
		var body struct {
			Items []string `json:"items"`
		}
		if err = json.Unmarshal(data, &body); err != nil || body.Items == nil {
			c.JSON(400, gin.H{"error": "invalid body"})
			return true
		}
		keys = body.Items
	}
	if h.applyConfigMutation(c, "api-keys.put", func(cfg *config.Config) (*APIKeyRotation, error) {
		cfg.APIKeys = append([]string(nil), keys...)
		return nil, nil
	}) {
		c.JSON(200, gin.H{"status": "ok"})
	}
	return true
}

type apiKeyPatch struct {
	Old   *string `json:"old"`
	New   *string `json:"new"`
	Index *int    `json:"index"`
	Value *string `json:"value"`
}

func (h *Handler) patchAPIKeysWithConfigApply(c *gin.Context) bool {
	if !h.requiresConfigApplyRequest(c) {
		return false
	}
	var body apiKeyPatch
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return true
	}
	if h.applyConfigMutation(c, "api-keys.patch", body.apply) {
		c.JSON(200, gin.H{"status": "ok"})
	}
	return true
}

func (body apiKeyPatch) apply(cfg *config.Config) (*APIKeyRotation, error) {
	index, replacement := -1, ""
	if body.Index != nil && body.Value != nil && *body.Index >= 0 && *body.Index < len(cfg.APIKeys) {
		index, replacement = *body.Index, *body.Value
		if body.Old != nil && *body.Old != cfg.APIKeys[index] || body.New != nil && *body.New != replacement {
			return nil, &ConfigApplyError{409, "conflicting_token_patch", "index/value and old/new identify different replacements"}
		}
	} else if body.Old != nil && body.New != nil {
		for i, key := range cfg.APIKeys {
			if key != *body.Old {
				continue
			}
			if index != -1 {
				return nil, &ConfigApplyError{409, "ambiguous_token_rotation", "multiple tokens match the old value"}
			}
			index = i
		}
		replacement = *body.New
		if index == -1 && !cfg.Grouping.Enabled {
			cfg.APIKeys = append(cfg.APIKeys, replacement)
			return nil, nil
		}
	} else {
		return nil, &ConfigApplyError{400, "invalid_body", "provide old/new or index/value"}
	}
	if index == -1 {
		return nil, &ConfigApplyError{404, "token_not_found", "old API token does not exist"}
	}
	rotation := &APIKeyRotation{Old: cfg.APIKeys[index], New: replacement}
	cfg.APIKeys[index] = replacement
	return rotation, nil
}

func (h *Handler) deleteAPIKeysWithConfigApply(c *gin.Context) bool {
	if !h.requiresConfigApplyRequest(c) {
		return false
	}
	if h.applyConfigMutation(c, "api-keys.delete", func(cfg *config.Config) (*APIKeyRotation, error) {
		if raw := c.Query("index"); raw != "" {
			index, err := strconv.Atoi(raw)
			if err == nil && index >= 0 && index < len(cfg.APIKeys) {
				cfg.APIKeys = append(cfg.APIKeys[:index], cfg.APIKeys[index+1:]...)
				return nil, nil
			}
		}
		if value := strings.TrimSpace(c.Query("value")); value != "" {
			keys := make([]string, 0, len(cfg.APIKeys))
			for _, key := range cfg.APIKeys {
				if strings.TrimSpace(key) != value {
					keys = append(keys, key)
				}
			}
			cfg.APIKeys = keys
			return nil, nil
		}
		return nil, &ConfigApplyError{400, "invalid_body", "missing index or value"}
	}) {
		c.JSON(200, gin.H{"status": "ok"})
	}
	return true
}
