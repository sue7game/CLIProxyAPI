package cliproxy

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

type groupingConfigTransition struct {
	beforeConfig       map[string]string
	afterConfig        map[string]string
	newCredentials     int
	removedCredentials int
}

func (g *groupingService) managedPolicyTransition(before grouping.Snapshot, cfg *config.Config, rotation *management.APIKeyRotation) (grouping.Snapshot, error) {
	if err := validateManagedTokenTransition(g.current.Load(), cfg, rotation); err != nil {
		return grouping.Snapshot{}, err
	}
	auths, err := g.collectSources(cfg, nil)
	if err != nil {
		return grouping.Snapshot{}, err
	}
	sources, err := g.initialIdentities(cfg, auths)
	if err != nil {
		return grouping.Snapshot{}, err
	}
	transition, err := newGroupingConfigTransition(g.current.Load(), cfg)
	if err != nil {
		return grouping.Snapshot{}, err
	}
	after := before.Clone()
	if err := g.applyTokenRotation(&after, rotation); err != nil {
		return grouping.Snapshot{}, err
	}
	seen := make(map[string]bool, len(sources))
	for _, source := range sources {
		if source.Kind == grouping.Token {
			source.ID = existingGroupingTokenID(after, source)
		}
		seen[source.ID] = true
		if err := transition.applySource(&after, source); err != nil {
			return grouping.Snapshot{}, err
		}
	}
	for id, identity := range after.Identities {
		if seen[id] || identity.State == grouping.Tombstone {
			continue
		}
		if _, controlled := transition.beforeConfig[id]; controlled {
			transition.removedCredentials++
		}
		if err := after.SetIdentityState(id, grouping.Tombstone); err != nil {
			return grouping.Snapshot{}, err
		}
	}
	if transition.newCredentials != 0 && transition.removedCredentials != 0 {
		return grouping.Snapshot{}, &management.ConfigApplyError{StatusCode: 409, Code: "ambiguous_credential_replacement", Message: "retain each existing grouping-id when editing credentials; replacing old IDs with new records requires explicit identity reconciliation"}
	}
	return after, after.Validate()
}

func newGroupingConfigTransition(before, after *config.Config) (*groupingConfigTransition, error) {
	oldSources, err := groupingConfigMaterials(before)
	if err != nil {
		return nil, err
	}
	newSources, err := groupingConfigMaterials(after)
	if err != nil {
		return nil, err
	}
	return &groupingConfigTransition{beforeConfig: oldSources, afterConfig: newSources}, nil
}

func groupingConfigMaterials(cfg *config.Config) (map[string]string, error) {
	auths, err := synthesizeGroupingConfigInventory(&synthesizer.SynthesisContext{Config: cfg, IDGenerator: synthesizer.NewStableIDGenerator()})
	if err != nil {
		return nil, err
	}
	materials := make(map[string]string, len(auths))
	for _, auth := range auths {
		material, err := groupingCredentialMaterial(auth)
		if err != nil {
			return nil, err
		}
		materials[auth.Attributes["grouping_id"]] = material
	}
	return materials, nil
}

func (t *groupingConfigTransition) applySource(snapshot *grouping.Snapshot, source grouping.Identity) error {
	old, exists := snapshot.Identities[source.ID]
	newMaterial, controlled := t.afterConfig[source.ID]
	oldMaterial, previouslyControlled := t.beforeConfig[source.ID]
	if !exists {
		if source.Kind == grouping.Credential {
			if controlled {
				t.newCredentials++
			} else {
				source.State = grouping.PendingRebind
			}
		}
		return snapshot.Register(source)
	}
	if old.Provider != source.Provider || old.Kind != source.Kind {
		return grouping.ErrConflict
	}
	if old.State == grouping.Tombstone {
		return snapshot.SetIdentityState(old.ID, grouping.PendingRebind)
	}
	if old.State != grouping.Active {
		return nil
	}
	if old.Fingerprint == source.Fingerprint {
		return nil
	}
	// An unrelated configuration PUT must not trust a coincident external file edit.
	if controlled && previouslyControlled && oldMaterial != newMaterial {
		return snapshot.ReplaceIdentity(old.ID, old.Fingerprint, source.Fingerprint)
	}
	return snapshot.SetIdentityState(old.ID, grouping.PendingRebind)
}

func validateManagedTokenTransition(before, after *config.Config, rotation *management.APIKeyRotation) error {
	oldKeys, newKeys := make(map[string]bool), make(map[string]bool)
	for _, key := range before.APIKeys {
		oldKeys[strings.TrimSpace(key)] = true
	}
	for _, key := range after.APIKeys {
		newKeys[strings.TrimSpace(key)] = true
	}
	added, removed := 0, 0
	for key := range newKeys {
		if !oldKeys[key] {
			added++
		}
	}
	for key := range oldKeys {
		if !newKeys[key] {
			removed++
		}
	}
	if added == 0 || removed == 0 {
		return nil
	}
	if rotation != nil && added == 1 && removed == 1 && oldKeys[rotation.Old] && !newKeys[rotation.Old] && newKeys[rotation.New] && !oldKeys[rotation.New] {
		return nil
	}
	return &management.ConfigApplyError{StatusCode: 409, Code: "ambiguous_token_rotation", Message: "rotate one API key with its explicit previous value to preserve the token group"}
}

func (g *groupingService) applyTokenRotation(snapshot *grouping.Snapshot, rotation *management.APIKeyRotation) error {
	if rotation == nil || rotation.Old == rotation.New {
		return nil
	}
	oldFingerprint, err := g.store.Fingerprint("token:"+sdkaccess.DefaultAccessProviderName, rotation.Old)
	if err != nil {
		return err
	}
	newFingerprint, err := g.store.Fingerprint("token:"+sdkaccess.DefaultAccessProviderName, rotation.New)
	if err != nil {
		return err
	}
	var id string
	for _, identity := range snapshot.Identities {
		if identity.Kind != grouping.Token || identity.Provider != sdkaccess.DefaultAccessProviderName {
			continue
		}
		if identity.Fingerprint == newFingerprint {
			return grouping.ErrConflict
		}
		if identity.Fingerprint == oldFingerprint {
			if id != "" || identity.State != grouping.Active {
				return grouping.ErrConflict
			}
			id = identity.ID
		}
	}
	if id == "" {
		return grouping.ErrNotFound
	}
	return snapshot.ReplaceIdentity(id, oldFingerprint, newFingerprint)
}
