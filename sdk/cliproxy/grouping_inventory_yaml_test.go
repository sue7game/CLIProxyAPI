package cliproxy

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	"gopkg.in/yaml.v3"
)

func TestGroupingInventoryYAMLEquivalentHomeDirectory(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	home := filepath.Dir(f.authDir)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	handler := &management.Handler{}
	handler.SetConfig(f.service.cfg)
	handler.SetConfigApplyHook(f.service.applyGroupingConfigMutation)
	before := f.snapshot(t)
	proposed := f.service.cfg.CloneForRuntime()
	proposed.AuthDir, proposed.Debug = "~/auths", true
	raw, err := yaml.Marshal(proposed)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest("PUT", "/config.yaml", bytes.NewReader(raw))
	handler.PutConfigYAML(c)
	if response.Code != 200 {
		t.Fatalf("equivalent directory failed real source transaction: %d %s", response.Code, response.Body.String())
	}
	if f.service.cfg.AuthDir != f.authDir || !f.service.cfg.Debug {
		t.Fatal("equivalent directory was not normalized before runtime publication")
	}
	if !reflect.DeepEqual(before.Identities, f.snapshot(t).Identities) {
		t.Fatal("equivalent directory changed registered source identities")
	}
	if _, err := os.Stat(filepath.Join(f.service.grouping.path, "config.pending")); !os.IsNotExist(err) {
		t.Fatalf("successful YAML transaction retained its pending journal: %v", err)
	}
}
