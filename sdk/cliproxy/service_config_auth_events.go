package cliproxy

import (
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func (s *Service) usesAuthoritativeConfigAuths(cfg *config.Config) bool {
	return s != nil && s.grouping != nil && s.grouping.enabled.Load() && cfg != nil && !cfg.Home.Enabled
}

// authoritativeConfigAuthUpdates runs under authUpdateMu. Watcher revisions only
// order watcher observations, not synchronous management commits. Treat config
// events as invalidations and resolve their contents from the accepted config.
func (s *Service) authoritativeConfigAuthUpdates(cfg *config.Config, updates []watcher.AuthUpdate) ([]watcher.AuthUpdate, error) {
	if !s.usesAuthoritativeConfigAuths(cfg) {
		return updates, nil
	}
	configIDs := s.configAuthUpdateIDs(updates)
	if len(configIDs) == 0 {
		return updates, nil
	}
	auths, err := synthesizeConfigAPIKeyAuths(cfg)
	if err != nil {
		return nil, err
	}
	desired := make(map[string]*coreauth.Auth, len(auths))
	for _, auth := range auths {
		if coreauth.IsConfigAPIKeyAuth(auth) {
			desired[auth.ID] = auth
		}
	}
	out := make([]watcher.AuthUpdate, 0, len(updates))
	for _, update := range updates {
		id := authUpdateID(update)
		if !configIDs[id] {
			out = append(out, update)
			continue
		}
		update.ID = id
		if next := desired[id]; next != nil {
			update.Action, update.Auth = watcher.AuthUpdateActionModify, next
		} else if current, ok := s.coreManager.GetByID(id); ok && coreauth.IsConfigAPIKeyAuth(current) {
			update.Action, update.Auth = watcher.AuthUpdateActionDelete, nil
		} else {
			continue
		}
		out = append(out, update)
	}
	return out, nil
}

func (s *Service) configAuthUpdateIDs(updates []watcher.AuthUpdate) map[string]bool {
	ids := make(map[string]bool)
	for _, update := range updates {
		switch update.Action {
		case watcher.AuthUpdateActionAdd, watcher.AuthUpdateActionModify:
			if coreauth.IsConfigAPIKeyAuth(update.Auth) {
				ids[authUpdateID(update)] = true
			}
		case watcher.AuthUpdateActionDelete:
			id := authUpdateID(update)
			current, _ := s.coreManager.GetByID(id)
			if coreauth.IsConfigAPIKeyAuth(update.Auth) || coreauth.IsConfigAPIKeyAuth(current) {
				ids[id] = true
			}
		}
	}
	return ids
}
