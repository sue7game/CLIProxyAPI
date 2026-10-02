package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// WithGroupingBackend installs local grouping administration behind management auth.
func WithGroupingBackend(backend groupingapi.Backend) ServerOption {
	return func(options *serverOptionConfig) { options.groupingBackend = backend }
}

// WithGroupingAuthHooks validates sources after custom preparation and finalizes
// their durable identity before existing runtime publication hooks execute.
func WithGroupingAuthHooks(prepare, persisted auth.PostAuthHook) ServerOption {
	return func(options *serverOptionConfig) {
		options.postAuthHook = composeGroupingAuthHooks(options.postAuthHook, prepare)
		options.postAuthPersistHook = composeGroupingAuthHooks(persisted, options.postAuthPersistHook)
	}
}

func composeGroupingAuthHooks(first, second auth.PostAuthHook) auth.PostAuthHook {
	return func(ctx context.Context, record *auth.Auth) error {
		if first != nil {
			if err := first(ctx, record); err != nil {
				return err
			}
		}
		if second != nil {
			return second(ctx, record)
		}
		return nil
	}
}

// BeginCredentialAccessActivation prevents direct-media admission during activation.
func (s *Server) BeginCredentialAccessActivation() (func(), error) {
	if s == nil || s.codexLiveHandler == nil {
		return func() {}, nil
	}
	return s.codexLiveHandler.BeginCredentialAccessActivation()
}

func (s *Server) groupingReadinessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/v0/management/") {
			c.Next()
			return
		}
		state := s.groupingReadiness.Load()
		if state&1 != 0 && (state&2 != 0 || s.handlers == nil || s.handlers.AuthManager == nil || !s.handlers.AuthManager.CredentialAccessPolicyEnabled()) {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "grouping enforcement is unavailable"})
			return
		}
		c.Next()
	}
}

func (s *Server) setGroupingReadiness(cfg *config.Config) {
	var state uint32
	if cfg != nil && cfg.Grouping.Enabled {
		state |= 1
	}
	if cfg != nil && cfg.Home.Enabled {
		state |= 2
	}
	s.groupingReadiness.Store(state)
}
