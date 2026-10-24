package cliproxy

import (
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

func TestGroupingV8IgnoredSourceAllowsUnrelatedManagementMutation(t *testing.T) {
	for _, position := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("ignored-at-%d", position), func(t *testing.T) {
			verifyGroupingIgnoredSourceMutation(t, position)
		})
	}
}

func verifyGroupingIgnoredSourceMutation(t *testing.T, position int) {
	t.Helper()
	f := newGroupingHTTPFixture(t)
	insertGroupingIgnoredSource(t, f.path, position)
	f.managed(t, http.MethodPost, "/grouping/initialize", gin.H{}, 0)
	before, identities := readGroupingIgnoredSourceConfig(t, f.path), f.snapshot(t).Identities
	if len(before.CodexKey) != 3 || before.CodexKey[position].GroupingID == "" {
		t.Fatal("ignored source did not receive its persistent identity")
	}
	var liveIDs []string
	for i, key := range before.CodexKey {
		if i != position {
			liveIDs = append(liveIDs, key.GroupingID)
		}
	}
	f.managed(t, http.MethodPatch, "/config/observability/logs/debug", true, 0)
	after := readGroupingIgnoredSourceConfig(t, f.path)
	if !f.service.cfg.Debug || len(f.service.cfg.CodexKey) != 2 || len(after.CodexKey) != 3 {
		t.Fatal("mutation blocked or revived an ignored source")
	}
	if !reflect.DeepEqual(before.CodexKey, after.CodexKey) || !reflect.DeepEqual(identities, f.snapshot(t).Identities) {
		t.Fatal("unrelated mutation changed source identities or bindings")
	}
	for i, key := range f.service.cfg.CodexKey {
		if key.GroupingID != liveIDs[i] {
			t.Fatal("duplicate records were associated by secret instead of source position")
		}
	}
	f.managed(t, http.MethodPatch, "/grouping/activation", gin.H{"enabled": true}, f.snapshot(t).Revision)
	f.managed(t, http.MethodPatch, "/config/observability/logs/debug", false, 0)
	if f.service.cfg.Debug || len(f.service.cfg.CodexKey) != 2 {
		t.Fatal("enabled policy blocked an unrelated mutation")
	}
}

func insertGroupingIgnoredSource(t *testing.T, path string, position int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	root := doc.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "codex-api-key" {
			continue
		}
		keys := root.Content[i+1]
		if len(keys.Content) != 2 {
			t.Fatal("fixture does not contain duplicate source records")
		}
		blank := new(yaml.Node)
		if err = blank.Encode(map[string]string{"api-key": ""}); err != nil {
			t.Fatal(err)
		}
		keys.Content = append(keys.Content[:position], append([]*yaml.Node{blank}, keys.Content[position:]...)...)
		raw, err = yaml.Marshal(&doc)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("legacy fixture has no source list")
}

func readGroupingIgnoredSourceConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err = yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return &cfg
}
