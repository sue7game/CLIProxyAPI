package cliproxy

import (
	"context"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func synthesizeConfigAPIKeyAuths(cfg *config.Config) ([]*coreauth.Auth, error) {
	return synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{
		Config: cfg, Now: time.Now(), IDGenerator: synthesizer.NewStableIDGenerator(),
	})
}

func (s *Service) prepareConfigAuthSynchronization(ctx context.Context, auths []*coreauth.Auth) ([]modelRegistrationTask, bool) {
	s.authUpdateMu.Lock()
	defer s.authUpdateMu.Unlock()
	needsAliasRebuild := s.retireObsoleteConfigAuths(ctx, auths)
	tasks := make([]modelRegistrationTask, 0, len(auths))
	for _, auth := range auths {
		if !coreauth.IsConfigAPIKeyAuth(auth) {
			continue
		}
		prepared := s.prepareCoreAuthForModelRegistration(ctx, auth)
		if prepared == nil {
			continue
		}
		needsAliasRebuild = true
		tasks = append(tasks, modelRegistrationTask{
			phase:    modelRegistrationPhaseConfigAPIKey,
			category: modelRegistrationCategory(prepared),
			run: func(compatCache *openAICompatibilityRegistrationCache) {
				if s.grouping != nil && s.grouping.enabled.Load() && s.shouldSkipModelRegistration(prepared) {
					return
				}
				s.completeModelRegistrationForAuthWithCache(ctx, prepared, compatCache)
			},
		})
	}
	return tasks, needsAliasRebuild
}

func (s *Service) retireObsoleteConfigAuths(ctx context.Context, auths []*coreauth.Auth) bool {
	desired := make(map[string]*coreauth.Auth, len(auths))
	for _, auth := range auths {
		if coreauth.IsConfigAPIKeyAuth(auth) {
			desired[auth.ID] = auth
		}
	}
	removed := false
	for _, current := range s.coreManager.List() {
		if !coreauth.IsConfigAPIKeyAuth(current) {
			continue
		}
		next := desired[current.ID]
		if next != nil && current.Attributes["grouping_id"] == next.Attributes["grouping_id"] {
			continue
		}
		// A duplicate's ordinal runtime ID can be reused by a different source.
		// Retire it first so overrides, sessions and scheduling state cannot transfer.
		s.applyCoreAuthRemoval(ctx, current.ID)
		removed = true
	}
	return removed
}

func (s *Service) retireReplacedConfigAuth(ctx context.Context, auth *coreauth.Auth) {
	if !coreauth.IsConfigAPIKeyAuth(auth) || s.grouping == nil || !s.grouping.enabled.Load() {
		return
	}
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()
	if !s.usesAuthoritativeConfigAuths(cfg) {
		return
	}
	current, ok := s.coreManager.GetByID(auth.ID)
	if ok && coreauth.IsConfigAPIKeyAuth(current) && current.Attributes["grouping_id"] != auth.Attributes["grouping_id"] {
		s.applyCoreAuthRemoval(ctx, auth.ID)
	}
}
