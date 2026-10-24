package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
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

// BeginManagementConfigMutation excludes legacy management writes through the
// persistence and runtime publication of a managed configuration transaction.
func (s *Server) BeginManagementConfigMutation() func() {
	if s == nil || s.mgmt == nil {
		return func() {}
	}
	return s.mgmt.BeginConfigMutationFence()
}

func (s *Server) groupingReadinessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isGroupingManagementPath(c.Request.URL.Path) {
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

func isGroupingManagementPath(path string) bool {
	if path == "/management.html" {
		return true
	}
	for _, prefix := range []string{"/v0/management", "/v8/management"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
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
