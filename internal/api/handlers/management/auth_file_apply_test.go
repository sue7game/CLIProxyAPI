package management

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestAuthFileApplyRunsBeforeParsingWritingOrRegistration(t *testing.T) {
	dir := t.TempDir()
	h := &Handler{cfg: &config.Config{AuthDir: dir, Grouping: config.GroupingConfig{Enabled: true}}}
	raw := []byte(`{"type":"codex","access_token":"new"}`)
	expected := errors.New("transaction rejected")
	h.SetAuthFileApplyHook(func(_ context.Context, path string, data []byte) error {
		if path != filepath.Join(dir, "new.json") || string(data) != string(raw) {
			t.Fatal("incorrect upload input")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("source written before hook")
		}
		data[0] = 'X'
		h.SetConfig(h.cfg.CloneForRuntime())
		return expected
	})
	if err := h.writeAuthFile(context.Background(), "../new.json", raw); !errors.Is(err, expected) {
		t.Fatalf("error=%v", err)
	}
	if raw[0] != '{' {
		t.Fatal("hook modified caller buffer")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected upload changed directory")
	}
}

func TestAuthFileApplyRequiresTransactionForEnabledGrouping(t *testing.T) {
	dir := t.TempDir()
	h := &Handler{cfg: &config.Config{AuthDir: dir, Grouping: config.GroupingConfig{Enabled: true}}}
	if err := h.writeAuthFile(context.Background(), "new.json", []byte(`{"type":"codex"}`)); err == nil {
		t.Fatal("grouping upload bypassed transaction")
	}
	if _, err := os.Stat(filepath.Join(dir, "new.json")); !os.IsNotExist(err) {
		t.Fatal("upload wrote source file")
	}
}
