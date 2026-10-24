package cliproxy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGroupingFileInitializationIsExplicitAndStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.json")
	before := []byte(`{"type":"codex","access_token":"test-only-token","account_id":"test-account","unknown":{"keep":true}}`)
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	changes, err := prepareGroupingFileIDs(dir)
	if err != nil || len(changes) != 1 {
		t.Fatalf("prepare: %d %v", len(changes), err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, before) {
		t.Fatal("planning modified source")
	}
	if err := writeGroupingSource(changes[0]); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(updated, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["grouping_id"] == "" || metadata["access_token"] != "test-only-token" || metadata["unknown"] == nil {
		t.Fatal("identity or original fields lost")
	}
	again, err := prepareGroupingFileIDs(dir)
	if err != nil || len(again) != 0 {
		t.Fatalf("retry was not idempotent: %v", err)
	}
}

func TestGroupingFileInitializationRefusesConflictAndDuplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.json")
	if err := os.WriteFile(path, []byte(`{"type":"codex"}`), 0600); err != nil {
		t.Fatal(err)
	}
	changes, err := prepareGroupingFileIDs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"type":"claude"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeGroupingSource(changes[0]); err == nil {
		t.Fatal("concurrent source edit overwritten")
	}
	if err := os.WriteFile(path, changes[0].after, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "copy.json"), changes[0].after, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareGroupingFileIDs(dir); err == nil {
		t.Fatal("duplicate source UUID accepted")
	}
}
