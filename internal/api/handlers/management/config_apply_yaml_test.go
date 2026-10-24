package management

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func configYAMLApplyRequest(h *Handler, authDir string) *httptest.ResponseRecorder {
	raw := fmt.Sprintf("auth-dir: %q\ngrouping:\n  enabled: true\napi-keys: [old-token]\n", authDir)
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest("PUT", "/config.yaml", strings.NewReader(raw))
	h.PutConfigYAML(c)
	return response
}

func TestConfigYAMLApplyNormalizesEquivalentAuthDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	authDir := filepath.Join(home, ".cli-proxy-api")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"~/.cli-proxy-api", `~\.cli-proxy-api`, "", authDir} {
		t.Run(path, func(t *testing.T) {
			h, source, _ := newConfigApplyTestHandler(t)
			source.AuthDir = authDir
			called := false
			h.SetConfigApplyHook(func(_ context.Context, request ConfigApplyRequest) error {
				called = true
				if request.Current.AuthDir != authDir || request.Proposed.AuthDir != authDir {
					t.Fatal("synchronous hook received an unresolved or changed auth directory")
				}
				_, err := os.ReadDir(request.Proposed.AuthDir)
				return err
			})
			response := configYAMLApplyRequest(h, path)
			if response.Code != 200 || !called || h.cfg.AuthDir != authDir {
				t.Fatalf("equivalent path was not applied: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestConfigYAMLApplyRejectsAuthDirMigration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, path := range []string{"~/other-auths", filepath.Join(home, "other-auths")} {
		t.Run(path, func(t *testing.T) {
			h, source, raw := newConfigApplyTestHandler(t)
			source.AuthDir = filepath.Join(home, ".cli-proxy-api")
			h.SetConfigApplyHook(func(context.Context, ConfigApplyRequest) error {
				t.Error("auth directory migration reached the synchronous transaction hook")
				return nil
			})
			response := configYAMLApplyRequest(h, path)
			if response.Code != 409 || !strings.Contains(response.Body.String(), "auth_dir_change_requires_restart") {
				t.Fatalf("migration was not rejected: %d %s", response.Code, response.Body.String())
			}
			assertConfigApplyUnchanged(t, h, source, raw)
		})
	}
}

func TestConfigYAMLApplyRejectsUnresolvableAuthDir(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	h, source, raw := newConfigApplyTestHandler(t)
	source.AuthDir = t.TempDir()
	h.SetConfigApplyHook(func(context.Context, ConfigApplyRequest) error {
		t.Error("unresolved auth directory reached the transaction hook")
		return nil
	})
	response := configYAMLApplyRequest(h, "~/auths")
	if response.Code != 422 {
		t.Fatalf("unresolved directory status=%d", response.Code)
	}
	assertConfigApplyUnchanged(t, h, source, raw)
}
