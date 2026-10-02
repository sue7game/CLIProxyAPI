package cliproxy

import (
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/groupingadmin"
)

func (g *groupingService) backend() (groupingapi.Backend, error) {
	return groupingadmin.New(groupingadmin.Options{
		Mutex:           &g.mu,
		Store:           func() *grouping.Store { return g.store },
		Enabled:         g.enabled.Load,
		Healthy:         g.healthy,
		Initialized:     func() bool { return g.installed },
		Catalog:         func() map[string]groupingadmin.Label { return g.catalog },
		ModelCatalog:    g.previewModelCatalog,
		BeforeMutation:  g.sourceTransactionIdle,
		Initialize:      g.initialize,
		Activation:      g.activate,
		Rebind:          g.rebind,
		OnPolicyChanged: g.notify,
	})
}
