package cliproxy

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type groupingAuthSourcePlan struct {
	change groupingFileChange
	cfg    *config.Config
	before grouping.Snapshot
	after  grouping.Snapshot
	auths  []*coreauth.Auth
}

func groupingAuthMetadata(raw []byte) (map[string]any, error) {
	var metadata map[string]any
	if len(raw) == 0 || len(raw) > 64<<20 || json.Unmarshal(raw, &metadata) != nil || metadata == nil {
		return nil, grouping.ErrInvalid
	}
	return metadata, nil
}

func groupingSourceUUID(metadata map[string]any) (string, error) {
	value, exists := metadata["grouping_id"]
	if !exists {
		return "", nil
	}
	id, ok := value.(string)
	parsed, err := uuid.Parse(id)
	if !ok || err != nil || parsed == uuid.Nil || parsed.String() != id {
		return "", grouping.ErrInvalid
	}
	return id, nil
}

func assignGroupingAuthFileID(before, raw []byte) ([]byte, error) {
	metadata, err := groupingAuthMetadata(raw)
	if err != nil {
		return nil, err
	}
	provided, err := groupingSourceUUID(metadata)
	if err != nil {
		return nil, err
	}
	id := ""
	if before != nil {
		old, err := groupingAuthMetadata(before)
		if err != nil {
			return nil, grouping.ErrConflict
		}
		id, err = groupingSourceUUID(old)
		if err != nil || id == "" || (provided != "" && provided != id) {
			return nil, grouping.ErrConflict
		}
	} else {
		if provided != "" {
			return nil, grouping.ErrConflict
		}
		generated, err := uuid.NewRandom()
		if err != nil {
			return nil, grouping.ErrUnavailable
		}
		id = generated.String()
	}
	metadata["grouping_id"] = id
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, grouping.ErrInvalid
	}
	return append(encoded, '\n'), nil
}

func (g *groupingService) synthesizeAuthSource(cfg *config.Config, path string, raw []byte) ([]*coreauth.Auth, error) {
	synthesis := &synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, Now: time.Now(), IDGenerator: synthesizer.NewStableIDGenerator()}
	if g.owner.pluginHost != nil {
		synthesis.PluginAuthParser = g.owner.pluginHost
	}
	auths, err := synthesizer.SynthesizeAuthFile(synthesis, path, raw)
	if err != nil {
		return nil, grouping.ErrInvalid
	}
	return auths, nil
}

func (g *groupingService) authSourceConfig() (*config.Config, error) {
	current := g.current.Load()
	if current == nil {
		return nil, grouping.ErrUnavailable
	}
	cfg := current.CloneForRuntime()
	dir, err := canonicalGroupingDirectory(cfg.AuthDir)
	if err != nil {
		return nil, err
	}
	cfg.AuthDir = dir
	return cfg, nil
}

func (g *groupingService) planAuthSource(path string, before, after []byte) (*groupingAuthSourcePlan, error) {
	cfg, err := g.authSourceConfig()
	if err != nil {
		return nil, err
	}
	snapshot, err := g.store.Snapshot()
	if err != nil {
		return nil, err
	}
	if err := g.validateAuthSourceBaseline(cfg, snapshot); err != nil {
		return nil, err
	}
	plan := &groupingAuthSourcePlan{change: groupingFileChange{path, before, after}, cfg: cfg, before: snapshot, after: snapshot.Clone()}
	all, err := g.collectAuthSourceChange(cfg, plan.change)
	if err != nil {
		return nil, err
	}
	for _, auth := range all {
		if filepath.Clean(auth.Attributes[coreauth.AttributePath]) == path {
			plan.auths = append(plan.auths, auth)
		}
	}
	// Multi-record sources need a provider-specific persisted child-ID mutation.
	if len(plan.auths) != 1 {
		return nil, grouping.ErrInvalid
	}
	if err := g.planAuthIdentity(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func (g *groupingService) collectAuthSourceChange(cfg *config.Config, change groupingFileChange) ([]*coreauth.Auth, error) {
	auths, err := g.collectSources(cfg, []groupingFileChange{change})
	if err != nil {
		return nil, grouping.ErrConflict
	}
	// collectSources enumerates existing directory entries, so stage new files explicitly.
	if change.before == nil {
		added, err := g.synthesizeAuthSource(cfg, change.path, change.after)
		if err != nil {
			return nil, err
		}
		auths = append(auths, added...)
	}
	if err := validateGroupingSources(auths); err != nil {
		return nil, grouping.ErrConflict
	}
	return auths, nil
}

func (g *groupingService) planAuthIdentity(plan *groupingAuthSourcePlan) error {
	hash, err := g.store.IdentityHasher()
	if err != nil {
		return err
	}
	identity, err := groupingCredentialIdentity(plan.auths[0], hash)
	if err != nil {
		return grouping.ErrInvalid
	}
	if plan.change.before == nil {
		if err := plan.after.Register(identity); err != nil {
			return err
		}
	} else {
		previous, err := g.synthesizeAuthSource(plan.cfg, plan.change.path, plan.change.before)
		if err != nil || len(previous) != 1 {
			return grouping.ErrConflict
		}
		old, err := groupingCredentialIdentity(previous[0], hash)
		if err != nil || !registeredGroupingSource(plan.before, old) || old.ID != identity.ID || old.Provider != identity.Provider {
			return grouping.ErrConflict
		}
		if err := plan.after.ReplaceIdentity(old.ID, old.Fingerprint, identity.Fingerprint); err != nil {
			return err
		}
	}
	return plan.after.Validate()
}

func (g *groupingService) validateAuthSourceBaseline(cfg *config.Config, snapshot grouping.Snapshot) error {
	auths, err := g.collectSources(cfg, nil)
	if err != nil {
		return g.failAuthSourceValidation()
	}
	hash, err := g.store.IdentityHasher()
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(auths))
	for _, auth := range auths {
		identity, err := groupingCredentialIdentity(auth, hash)
		old, exists := snapshot.Identities[identity.ID]
		if err != nil || !exists || old.Kind != grouping.Credential ||
			old.State == grouping.Active && !registeredGroupingSource(snapshot, identity) {
			return g.failAuthSourceValidation()
		}
		seen[identity.ID] = true
	}
	for id, identity := range snapshot.Identities {
		if identity.Kind == grouping.Credential && identity.State == grouping.Active && !seen[id] {
			return g.failAuthSourceValidation()
		}
	}
	g.sourcesUnavailable.Store(false)
	return nil
}

func (g *groupingService) failAuthSourceValidation() error {
	g.sourcesUnavailable.Store(true)
	return grouping.ErrConflict
}

func (g *groupingService) checkAuthSourceBaseline() error {
	cfg, err := g.authSourceConfig()
	if err != nil {
		return g.failAuthSourceValidation()
	}
	snapshot, err := g.store.Snapshot()
	if err != nil {
		return err
	}
	return g.validateAuthSourceBaseline(cfg, snapshot)
}

func (g *groupingService) sourceIntentCredentialIDs(path, kind string, raw []byte) ([]string, error) {
	if kind == "config" {
		return nil, nil
	}
	cfg, err := g.authSourceConfig()
	if err != nil {
		return nil, err
	}
	auths, err := g.synthesizeAuthSource(cfg, path, raw)
	if err != nil || len(auths) == 0 || validateGroupingSources(auths) != nil {
		return nil, grouping.ErrInvalid
	}
	ids := make([]string, 0, len(auths))
	for _, auth := range auths {
		identity, err := groupingCredentialIdentity(auth, func(_, material string) (string, error) { return material, nil })
		if err != nil {
			return nil, err
		}
		ids = append(ids, identity.ID)
	}
	slices.Sort(ids)
	return ids, nil
}
