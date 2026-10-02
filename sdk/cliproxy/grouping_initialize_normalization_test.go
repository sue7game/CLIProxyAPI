package cliproxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestGroupingInitializationKeepsDuplicatesWithoutResurrectingInvalidSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte(`codex-api-key:
  - api-key: fixture-ignored-no-base
  - api-key: fixture-duplicate
    base-url: https://example.invalid/v1
  - api-key: fixture-duplicate
    base-url: https://example.invalid/v1
openai-compatibility:
  - name: invalid-no-base
    api-key-entries:
      - api-key: fixture-invalid
`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	current, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	prepared, change, err := prepareGroupingConfig(path, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.CodexKey) != 2 || len(prepared.OpenAICompatibility) != 0 {
		t.Fatal("initialization resurrected normalized invalid sources or collapsed duplicates")
	}
	if prepared.CodexKey[0].GroupingID == "" || prepared.CodexKey[0].GroupingID == prepared.CodexKey[1].GroupingID {
		t.Fatal("duplicate records do not have independent IDs")
	}
	if err := writeGroupingSource(*change); err != nil {
		t.Fatal(err)
	}
	reloaded, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.CodexKey) != 2 || len(reloaded.OpenAICompatibility) != 0 {
		t.Fatal("persisted initialization changed normalization semantics")
	}
}
