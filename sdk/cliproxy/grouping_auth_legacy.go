package cliproxy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// commitLegacyAuthFile retains the pre-grouping upload behavior, including a
// symlinked auth directory and SDK configurations without a configuration file.
func (g *groupingService) commitLegacyAuthFile(path string, raw []byte) (*groupingAuthSourcePlan, error) {
	cfg := g.current.Load().CloneForRuntime()
	dir, err := filepath.Abs(cfg.AuthDir)
	if err != nil {
		return nil, grouping.ErrInvalid
	}
	path, err = filepath.Abs(path)
	if err != nil || filepath.Dir(path) != dir || !strings.EqualFold(filepath.Ext(path), ".json") {
		return nil, grouping.ErrInvalid
	}
	metadata, err := groupingAuthMetadata(raw)
	if err != nil {
		return nil, err
	}
	cfg.AuthDir = dir
	auths, err := g.synthesizeAuthSource(cfg, path, raw)
	if err != nil {
		return nil, err
	}
	if len(auths) == 0 {
		auths = []*coreauth.Auth{legacyGroupingAuthFallback(path, metadata)}
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return nil, grouping.ErrUnavailable
	}
	return &groupingAuthSourcePlan{cfg: cfg, auths: auths}, nil
}

func legacyGroupingAuthFallback(path string, metadata map[string]any) *coreauth.Auth {
	coreauth.NormalizeCredentialMetadata(metadata)
	provider, _ := metadata["type"].(string)
	if provider == "" {
		provider = "unknown"
	}
	label := provider
	if email, ok := metadata["email"].(string); ok && email != "" {
		label = email
	}
	id := filepath.Base(path)
	if runtime.GOOS == "windows" {
		id = strings.ToLower(id)
	}
	return &coreauth.Auth{ID: id, FileName: filepath.Base(path), Provider: provider,
		Label: label, Status: coreauth.StatusActive, Metadata: metadata, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		Attributes: map[string]string{coreauth.AttributePath: path, coreauth.AttributeSource: path}}
}
