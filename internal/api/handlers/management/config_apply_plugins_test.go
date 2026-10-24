package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func pluginApplyContext(method, id string) (*gin.Context, *httptest.ResponseRecorder) {
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Request = httptest.NewRequest(method, "/plugins/"+id, nil)
	return c, response
}

func pluginInstallApplyFixture(t *testing.T) *Handler {
	t.Helper()
	archive := makeManagementPluginStoreZip(t, "sample-provider"+managementPluginExtension(runtime.GOOS), "transaction-library")
	checksum := sha256.Sum256(archive)
	url := "https://downloads.example/plugin.zip"
	return &Handler{
		cfg:            &config.Config{Plugins: config.PluginsConfig{Dir: t.TempDir()}},
		configFilePath: writeTestConfigFile(t), pluginStoreRegistryURL: "https://registry.example/registry.json",
		pluginStoreHTTPClient: fakePluginStoreHTTPClient{
			"https://registry.example/registry.json": directRegistryJSON(url, hex.EncodeToString(checksum[:])), url: archive,
		},
	}
}

func TestPluginInstallConfigApplyIsSynchronousAndIsolated(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(strconv.FormatBool(reject), func(t *testing.T) {
			h := pluginInstallApplyFixture(t)
			source, before := h.cfg, h.cfg.CloneForRuntime()
			raw, err := os.ReadFile(h.configFilePath)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
				called = true
				if !reflect.DeepEqual(source, before) || req.Operation != "plugin.install" {
					t.Fatal("shared configuration mutated")
				}
				if !pluginInstanceEnabled(req.Proposed.Plugins.Configs["sample-provider"]) {
					t.Fatal("candidate missing installed plugin")
				}
				if reject {
					return errors.New("reject")
				}
				h.SetConfig(req.Proposed.CloneForRuntime())
				return nil
			})
			c, response := pluginApplyContext("POST", "sample-provider")
			h.InstallPluginFromStore(c)
			if !called {
				t.Fatal("install bypassed sync transaction")
			}
			if reject {
				if response.Code != 500 || !strings.Contains(response.Body.String(), `"file_installed":true`) || !strings.Contains(response.Body.String(), `"recovery_required":true`) {
					t.Fatalf("response=%d %s", response.Code, response.Body.String())
				}
				if h.cfg != source {
					t.Fatal("rejection published config")
				}
			} else if response.Code != 200 || h.cfg == source {
				t.Fatalf("successful transaction not published: %d", response.Code)
			}
			after, err := os.ReadFile(h.configFilePath)
			if err != nil || string(after) != string(raw) {
				t.Fatal("handler wrote configuration outside transaction owner")
			}
			if !reflect.DeepEqual(source, before) {
				t.Fatal("original configuration mutated")
			}
		})
	}
}

func pluginDeleteApplyFixture(t *testing.T) (*Handler, string) {
	t.Helper()
	dir := writeManagementPluginFile(t, "sample")
	h := &Handler{
		cfg:            &config.Config{Plugins: config.PluginsConfig{Dir: dir, Configs: map[string]config.PluginInstanceConfig{"sample": pluginConfigFromYAML(t, "enabled: true\n")}}},
		configFilePath: writeTestConfigFile(t),
	}
	path, err := pluginFilePath(dir, "sample")
	if err != nil || path == "" {
		t.Fatalf("plugin fixture: %v", err)
	}
	return h, path
}

func TestPluginDeleteConfigApplyReportsPartialFailure(t *testing.T) {
	h, path := pluginDeleteApplyFixture(t)
	source, before := h.cfg, h.cfg.CloneForRuntime()
	h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
		if req.Operation != "plugin.delete" || !reflect.DeepEqual(before, source) {
			t.Fatal("shared configuration mutated")
		}
		if _, ok := req.Proposed.Plugins.Configs["sample"]; ok {
			t.Fatal("candidate retained deleted plugin")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("file operation not performed")
		}
		return &ConfigApplyError{409, "conflict", "configuration changed"}
	})
	c, response := pluginApplyContext("DELETE", "sample")
	h.DeletePlugin(c)
	if response.Code != 409 || !strings.Contains(response.Body.String(), `"file_deleted":true`) || !strings.Contains(response.Body.String(), `"recovery_required":true`) {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	if h.cfg != source || !reflect.DeepEqual(source, before) {
		t.Fatal("rejection corrupted shared configuration")
	}
}

func TestPluginDeleteConfigApplyPublishesBeforeSuccess(t *testing.T) {
	h, _ := pluginDeleteApplyFixture(t)
	source := h.cfg
	h.SetConfigApplyHook(func(_ context.Context, req ConfigApplyRequest) error {
		h.SetConfig(req.Proposed.CloneForRuntime())
		return nil
	})
	c, response := pluginApplyContext("DELETE", "sample")
	h.DeletePlugin(c)
	if response.Code != 200 || h.cfg == source {
		t.Fatalf("status=%d", response.Code)
	}
	if _, ok := h.cfg.Plugins.Configs["sample"]; ok {
		t.Fatal("configuration not published")
	}
	if _, ok := source.Plugins.Configs["sample"]; !ok {
		t.Fatal("source mutated")
	}
}

func TestPluginDeleteLegacySaveFailureDoesNotMutateSharedConfig(t *testing.T) {
	h, _ := pluginDeleteApplyFixture(t)
	source, before := h.cfg, h.cfg.CloneForRuntime()
	h.configFilePath = filepath.Join(t.TempDir(), "missing", "config.yaml")
	c, response := pluginApplyContext("DELETE", "sample")
	h.DeletePlugin(c)
	if response.Code != 500 || !strings.Contains(response.Body.String(), `"file_deleted":true`) {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	if h.cfg != source || !reflect.DeepEqual(source, before) {
		t.Fatal("failed save corrupted config")
	}
}

func TestPluginConfigApplyRejectsChangedSelectionAfterFileOperation(t *testing.T) {
	h, path := pluginDeleteApplyFixture(t)
	expected := pluginConfigExpectation{directory: h.cfg.Plugins.Dir, original: h.cfg.Plugins.Configs["sample"], configured: true}
	updated := h.cfg.CloneForRuntime()
	updated.Plugins.Configs["sample"] = pluginConfigFromYAML(t, "enabled: false\n")
	h.SetConfig(updated)
	h.SetConfigApplyHook(func(context.Context, ConfigApplyRequest) error {
		t.Fatal("stale plugin operation reached hook")
		return nil
	})
	c, response := pluginApplyContext("DELETE", "sample")
	if h.commitDeletedPluginConfig(c, "sample", path, true, expected) {
		t.Fatal("stale selection committed")
	}
	if response.Code != 409 || !strings.Contains(response.Body.String(), `"file_deleted":true`) {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	if h.cfg == updated || !reflect.DeepEqual(h.cfg, updated) || pluginInstanceEnabled(h.cfg.Plugins.Configs["sample"]) {
		t.Fatal("newer config overwritten")
	}
}
