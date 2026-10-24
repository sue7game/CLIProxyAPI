package management

import (
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

func (h *Handler) applyConfigAuthStatusV8(c *gin.Context, auth *coreauth.Auth, disabled bool) bool {
	ok := h.applyConfigV8RuntimeMutation(c, func(candidate *config.Config) error {
		before := candidate.CloneForRuntime()
		handled, err := toggleConfigAPIKeyExcludedAll(candidate, auth, disabled)
		if err != nil {
			return &ConfigApplyError{409, "credential_status_failed", "configuration credential status could not be changed"}
		}
		if !handled {
			return &ConfigApplyError{404, "credential_not_found", "configuration credential was not found"}
		}
		return validateV8StatusSource(before, candidate, auth.Attributes["grouping_id"])
	}, projectV8CredentialStatus)
	if ok {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "disabled": disabled, "via": "config:excluded-models", "excluded_pattern": configAPIKeyDisablePattern})
	}
	return true
}

func projectV8CredentialStatus(doc *configV8Document, before, after *config.Config) error {
	if _, err := config.PrepareGroupingConfigDocument(doc.data, before); err != nil {
		return &ConfigApplyError{409, "credential_identity_changed", "credential source changed; refresh before changing status"}
	}
	for _, family := range v8CredentialStatusFamilies(before, after) {
		if reflect.DeepEqual(family.before, family.after) {
			continue
		}
		if err := projectV8FamilyStatus(doc.root, family.name, family.before, family.after); err != nil {
			return err
		}
	}
	return nil
}

type v8CredentialStatusFamily struct {
	name   string
	before any
	after  any
}

func v8CredentialStatusFamilies(before, after *config.Config) []v8CredentialStatusFamily {
	return []v8CredentialStatusFamily{
		{"gemini", before.GeminiKey, after.GeminiKey},
		{"interactions", before.InteractionsKey, after.InteractionsKey},
		{"claude", before.ClaudeKey, after.ClaudeKey},
		{"codex", before.CodexKey, after.CodexKey},
		{"xai", before.XAIKey, after.XAIKey},
		{"meta", before.MetaKey, after.MetaKey},
		{"vertex", before.VertexCompatAPIKey, after.VertexCompatAPIKey},
	}
}

func validateV8StatusSource(before, after *config.Config, identity string) error {
	if identity == "" {
		if before.Grouping.Enabled {
			return &ConfigApplyError{409, "credential_identity_changed", "credential identity is unavailable; refresh before changing status"}
		}
		return nil
	}
	for _, family := range v8CredentialStatusFamilies(before, after) {
		old, next := reflect.ValueOf(family.before), reflect.ValueOf(family.after)
		for i := 0; i < old.Len(); i++ {
			if reflect.DeepEqual(old.Index(i).Interface(), next.Index(i).Interface()) {
				continue
			}
			if old.Index(i).FieldByName("GroupingID").String() != identity {
				return &ConfigApplyError{409, "credential_identity_changed", "credential selection changed; refresh before changing status"}
			}
		}
	}
	return nil
}

func projectV8FamilyStatus(root *yaml.Node, name string, before, after any) error {
	old, next := new(yaml.Node), new(yaml.Node)
	if err := old.Encode(before); err != nil {
		return err
	}
	if err := next.Encode(after); err != nil {
		return err
	}
	groups := configV8Node(root, []string{"api-keys", name})
	var keys []*yaml.Node
	if groups != nil {
		for _, group := range groups.Content {
			if list := configV8Node(group, []string{"keys"}); list != nil {
				keys = append(keys, list.Content...)
			}
		}
	}
	var err error
	keys, err = matchV8StatusSourceKeys(keys, old.Content)
	if err != nil {
		return err
	}
	if len(keys) != len(next.Content) {
		return &ConfigApplyError{409, "credential_identity_changed", "credential source sequence changed"}
	}
	for i, key := range keys {
		a, b := configV8Node(old.Content[i], []string{"excluded-models"}), configV8Node(next.Content[i], []string{"excluded-models"})
		var previous, proposed []string
		if a != nil {
			_ = a.Decode(&previous)
		}
		if b != nil {
			_ = b.Decode(&proposed)
		}
		if reflect.DeepEqual(previous, proposed) {
			continue
		}
		if len(proposed) == 0 {
			b = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		}
		// Empty [] overrides inherited exclusions; null would inherit them again.
		*configV8Path(key, []string{"excluded-models"}) = *b
	}
	return nil
}

func matchV8StatusSourceKeys(keys, runtime []*yaml.Node) ([]*yaml.Node, error) {
	byID := make(map[string]*yaml.Node, len(keys))
	for _, key := range keys {
		if id := configV8Node(key, []string{"grouping-id"}); id != nil && id.Value != "" {
			if byID[id.Value] != nil {
				return nil, &ConfigApplyError{409, "credential_identity_changed", "credential identity is ambiguous"}
			}
			byID[id.Value] = key
		}
	}
	matched := make([]*yaml.Node, len(runtime))
	for i, record := range runtime {
		if id := configV8Node(record, []string{"grouping-id"}); id != nil && id.Value != "" {
			matched[i] = byID[id.Value]
		} else if len(keys) == len(runtime) {
			matched[i] = keys[i]
		}
		if matched[i] == nil {
			return nil, &ConfigApplyError{409, "credential_identity_changed", "credential source sequence changed"}
		}
	}
	return matched, nil
}
