package cliproxy

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

// previewModelCatalog runs under g.mu and captures one model-registration view.
// Bindings are evaluated by the caller against this same detached catalog for
// both policies, including while enforcement is disabled. No upstream is called.
func (g *groupingService) previewModelCatalog(ctx context.Context, policy grouping.Snapshot) (map[string][]string, error) {
	if ctx == nil || ctx.Err() != nil || !g.healthy() || g.store == nil || g.owner.coreManager == nil {
		return nil, grouping.ErrUnavailable
	}
	hash, err := g.store.IdentityHasher()
	if err != nil {
		return nil, err
	}
	clients := make(map[string]string)
	clientIDs := make([]string, 0)
	for _, auth := range g.owner.coreManager.List() {
		if auth == nil || auth.EffectiveDisabled() {
			continue
		}
		identity, err := groupingCredentialIdentity(auth, hash)
		if err != nil {
			return nil, grouping.ErrUnavailable
		}
		known, exists := policy.Identities[identity.ID]
		if !exists || known.State != grouping.Active {
			continue
		}
		if known.Kind != grouping.Credential || known.Provider != identity.Provider || known.Fingerprint != identity.Fingerprint {
			return nil, grouping.ErrUnavailable
		}
		clients[auth.ID] = identity.ID
		clientIDs = append(clientIDs, auth.ID)
	}
	models := registry.GetGlobalRegistry().ModelIDsForClients(clientIDs)
	catalog := make(map[string][]string, len(clients))
	for clientID, identityID := range clients {
		catalog[identityID] = append(catalog[identityID], models[clientID]...)
	}
	return catalog, nil
}
