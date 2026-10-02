package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func (g *groupingService) collectSources(cfg *config.Config, changes []groupingFileChange) ([]*coreauth.Auth, error) {
	synthesis := &synthesizer.SynthesisContext{Config: cfg, AuthDir: cfg.AuthDir, Now: time.Now(), IDGenerator: synthesizer.NewStableIDGenerator()}
	if g.owner.pluginHost != nil {
		synthesis.PluginAuthParser = g.owner.pluginHost
	}
	auths, err := synthesizeGroupingConfigInventory(synthesis)
	if err != nil {
		return nil, fmt.Errorf("grouping: configuration credential synthesis failed")
	}
	staged := make(map[string][]byte, len(changes))
	for _, change := range changes {
		staged[change.path] = change.after
	}
	entries, err := os.ReadDir(cfg.AuthDir)
	if err != nil {
		return nil, fmt.Errorf("grouping: credential directory unavailable")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		path := filepath.Join(cfg.AuthDir, entry.Name())
		data, ok := staged[path]
		if !ok {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				return nil, fmt.Errorf("grouping: credential source must be a regular file")
			}
			data, err = os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("grouping: credential source unavailable")
			}
		}
		var metadata map[string]json.RawMessage
		if err := json.Unmarshal(data, &metadata); err != nil || metadata == nil {
			return nil, fmt.Errorf("grouping: invalid credential source JSON")
		}
		items, err := synthesizer.SynthesizeAuthFile(synthesis, path, data)
		if err != nil {
			return nil, fmt.Errorf("grouping: credential source synthesis failed")
		}
		auths = append(auths, items...)
	}
	return auths, validateGroupingSources(auths)
}

func validateGroupingSources(auths []*coreauth.Auth) error {
	ids := make(map[string]bool, len(auths))
	runtimeIDs := make(map[string]bool, len(auths))
	for _, auth := range auths {
		identity, err := groupingCredentialIdentity(auth, func(_, material string) (string, error) { return material, nil })
		if err != nil {
			return fmt.Errorf("grouping: source lacks a valid independent identity or stable account identifier")
		}
		if ids[identity.ID] || runtimeIDs[auth.ID] {
			return fmt.Errorf("grouping: duplicate logical or runtime credential identity")
		}
		ids[identity.ID], runtimeIDs[auth.ID] = true, true
	}
	return nil
}

func (g *groupingService) initialIdentities(cfg *config.Config, auths []*coreauth.Auth) ([]grouping.Identity, error) {
	return groupingSourceIdentities(g.store, cfg, auths)
}

func groupingSourceIdentities(store *grouping.Store, cfg *config.Config, auths []*coreauth.Auth) ([]grouping.Identity, error) {
	hash, err := store.IdentityHasher()
	if err != nil {
		return nil, err
	}
	identities := make([]grouping.Identity, 0, len(auths)+len(cfg.APIKeys))
	for _, auth := range auths {
		identity, err := groupingCredentialIdentity(auth, hash)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	seen := make(map[string]bool)
	for _, key := range cfg.APIKeys {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		fingerprint, err := hash("token:"+sdkaccess.DefaultAccessProviderName, key)
		if err != nil {
			return nil, err
		}
		id, err := uuid.NewRandom()
		if err != nil {
			return nil, grouping.ErrUnavailable
		}
		identities = append(identities, grouping.Identity{Binding: grouping.Binding{ID: id.String(), Kind: grouping.Token, GroupID: grouping.AllGroups, State: grouping.Active}, Provider: sdkaccess.DefaultAccessProviderName, Fingerprint: fingerprint})
	}
	return identities, nil
}

func (g *groupingService) publishSources(ctx context.Context, cfg *config.Config, auths []*coreauth.Auth) error {
	g.current.Store(cfg.CloneForRuntime())
	if g.owner.coreManager == nil {
		return fmt.Errorf("grouping: credential manager is unavailable")
	}
	g.owner.coreManager.SetConfig(cfg)
	registrationCtx := coreauth.WithSkipPersist(ctx)
	for _, auth := range auths {
		if _, ok := g.owner.coreManager.GetByID(auth.ID); ok {
			if _, err := g.owner.coreManager.Update(registrationCtx, auth); err != nil {
				return fmt.Errorf("grouping: source publication failed")
			}
		} else if _, err := g.owner.coreManager.Register(registrationCtx, auth); err != nil {
			return fmt.Errorf("grouping: source registration failed")
		}
	}
	return nil
}
