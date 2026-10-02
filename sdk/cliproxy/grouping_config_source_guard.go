package cliproxy

import (
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

func validateManagedGroupingSourceDocument(data []byte, current *config.Config) error {
	if current == nil {
		return grouping.ErrUnavailable
	}
	var source config.Config
	if err := yaml.Unmarshal(data, &source); err != nil {
		return managedGroupingSourceConflict()
	}
	actual := managedGroupingSourceConfig(&source)
	if err := config.ValidateGroupingCredentialIDs(actual); err != nil {
		return managedGroupingSourceConflict()
	}
	// A fresh disk ETag does not prove that the watcher accepted these sources.
	// Compare the old document, never the proposed edit, with accepted state.
	if !reflect.DeepEqual(actual, managedGroupingSourceConfig(current)) {
		return managedGroupingSourceConflict()
	}
	return nil
}

func managedGroupingSourceConfig(source *config.Config) *config.Config {
	result := &config.Config{Grouping: config.GroupingConfig{Enabled: true}}
	copyGroupingCredentialLists(result, source)
	result = result.CloneForRuntime()
	normalizeGroupingCredentialLists(result)
	seen := make(map[string]bool)
	for _, key := range source.APIKeys {
		key = strings.TrimSpace(key)
		if key != "" && !seen[key] {
			result.APIKeys = append(result.APIKeys, key)
			seen[key] = true
		}
	}
	sort.Strings(result.APIKeys)
	return result
}

func (g *groupingService) validateManagedGroupingConfigPolicy(snapshot grouping.Snapshot) error {
	cfg := g.current.Load()
	if cfg == nil || g.store == nil {
		return grouping.ErrUnavailable
	}
	auths, err := synthesizeGroupingConfigInventory(&synthesizer.SynthesisContext{Config: cfg, IDGenerator: synthesizer.NewStableIDGenerator()})
	if err != nil {
		return managedGroupingSourceConflict()
	}
	hash, err := g.store.IdentityHasher()
	if err != nil {
		return err
	}
	for _, auth := range auths {
		source, err := groupingCredentialIdentity(auth, hash)
		if err != nil {
			return managedGroupingSourceConflict()
		}
		registered, exists := snapshot.Identities[source.ID]
		if !exists || registered.Kind != source.Kind || registered.Provider != source.Provider {
			return managedGroupingSourceConflict()
		}
		if registered.State == grouping.Active && registered.Fingerprint != source.Fingerprint {
			return managedGroupingSourceConflict()
		}
	}
	return validateManagedGroupingTokenPolicy(snapshot, cfg, hash)
}

func validateManagedGroupingTokenPolicy(snapshot grouping.Snapshot, cfg *config.Config, hash groupingHasher) error {
	registered := make(map[string]int)
	for _, identity := range snapshot.Identities {
		if identity.Kind == grouping.Token && identity.Provider == sdkaccess.DefaultAccessProviderName {
			registered[identity.Fingerprint]++
		}
	}
	for _, token := range cfg.APIKeys {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		fingerprint, err := hash("token:"+sdkaccess.DefaultAccessProviderName, token)
		if err != nil {
			return err
		}
		if registered[fingerprint] != 1 {
			return managedGroupingSourceConflict()
		}
	}
	return nil
}

func managedGroupingSourceConflict() error {
	return &management.ConfigApplyError{
		StatusCode: http.StatusConflict,
		Code:       "grouping_source_changed",
		Message:    "persisted credential or token sources do not match accepted state; reload and reconcile identities before retrying",
	}
}
