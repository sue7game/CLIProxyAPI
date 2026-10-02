package cliproxy

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"gopkg.in/yaml.v3"
)

func TestGroupingV8UninitializedHTTPWritePreservesInode(t *testing.T) {
	f := newGroupingHTTPFixture(t)
	before, err := os.Stat(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.managed(t, http.MethodPatch, "/config/observability/logs/debug", true, 0)
	after, err := os.Stat(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !f.service.cfg.Debug {
		t.Fatal("v8 save before initialization replaced the inode or failed to publish")
	}
	if f.service.grouping.store != nil {
		t.Fatal("ordinary v8 save implicitly initialized grouping")
	}
}

func TestGroupingUninitializedConfigPreservesInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	before := []byte("config-version: 8\nobservability:\n  logs:\n    debug: false\n")
	after := []byte("config-version: 8\nobservability:\n  logs:\n    debug: true\n")
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	infoBefore, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeUninitializedGroupingConfig(groupingFileChange{path, before, after}); err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(infoBefore, infoAfter) || infoAfter.Mode().Perm() != infoBefore.Mode().Perm() {
		t.Fatal("uninitialized configuration write replaced the inode or permissions")
	}
	contents, err := os.ReadFile(path)
	var got, want any
	if err != nil || yaml.Unmarshal(contents, &got) != nil || yaml.Unmarshal(after, &want) != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("configuration write did not persist the requested document: %v", err)
	}
}

func TestGroupingUninitializedConfigRejectsStaleDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	current := []byte("config-version: 8\n# External modification\n")
	if err := os.WriteFile(path, current, 0600); err != nil {
		t.Fatal(err)
	}
	err := writeUninitializedGroupingConfig(groupingFileChange{
		path: path, before: []byte("config-version: 8\n"), after: []byte("config-version: 8\nserver: {}\n"),
	})
	if !errors.Is(err, grouping.ErrConflict) {
		t.Fatalf("stale document error = %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != string(current) {
		t.Fatalf("stale write changed the external document: %v", err)
	}
}
