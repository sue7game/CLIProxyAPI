package cliproxy

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func (g *groupingService) applyPluginAuthFile(ctx context.Context, name string, data []byte) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, "/\\") || !strings.EqualFold(filepath.Ext(name), ".json") {
		return "", grouping.ErrInvalid
	}
	cfg := g.current.Load()
	if cfg == nil {
		return "", grouping.ErrUnavailable
	}
	path := filepath.Join(cfg.AuthDir, name)
	if err := g.applyAuthFile(ctx, path, data); err != nil {
		return "", err
	}
	return path, nil
}
