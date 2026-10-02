package management

import (
	"net/http"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestManagementAuthenticationConcurrentConfigPublication(t *testing.T) {
	h := &Handler{cfg: &config.Config{}, envSecret: "test-management", failedAttempts: make(map[string]*attemptInfo)}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			h.SetConfig(&config.Config{})
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			allowed, _, _ := h.AuthenticateManagementKey("127.0.0.1", true, "test-management")
			if !allowed {
				t.Error("valid management authentication rejected")
				return
			}
		}
	}()
	workers.Wait()
}

func TestManagementLocalPasswordStillRequiresConfiguredSecret(t *testing.T) {
	h := &Handler{cfg: &config.Config{}, localPassword: "local-password", failedAttempts: make(map[string]*attemptInfo)}
	allowed, status, _ := h.AuthenticateManagementKey("127.0.0.1", true, "local-password")
	if allowed || status != http.StatusForbidden {
		t.Fatal("local password bypassed missing management secret")
	}
	h.envSecret = "configured-secret"
	allowed, _, _ = h.AuthenticateManagementKey("127.0.0.1", true, "local-password")
	if !allowed {
		t.Fatal("local password rejected with management secret configured")
	}
}
