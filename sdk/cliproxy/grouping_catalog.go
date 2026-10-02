package cliproxy

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/groupingadmin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func (g *groupingService) refreshCatalog(cfg *config.Config, auths []*coreauth.Auth) {
	catalog := make(map[string]groupingadmin.Label)
	for id, path := range config.GroupingCredentialSources(cfg) {
		catalog[id] = groupingadmin.Label{Label: path, Source: "config.yaml"}
	}
	for _, auth := range auths {
		if coreauth.IsConfigAPIKeyAuth(auth) {
			continue
		}
		id := auth.Attributes["grouping_id"]
		if id == "" {
			id, _ = auth.Metadata["grouping_id"].(string)
		}
		name := groupingDisplayText(filepath.Base(auth.FileName), 180)
		if name == "." || name == "" {
			continue
		}
		catalog[id] = groupingadmin.Label{Label: name, Source: "auth-dir"}
	}
	snapshot, err := g.store.Snapshot()
	if err != nil {
		return
	}
	byFingerprint := make(map[string]string)
	for id, identity := range snapshot.Identities {
		if identity.Kind == grouping.Token && identity.Provider == sdkaccess.DefaultAccessProviderName {
			byFingerprint[identity.Fingerprint] = id
		}
	}
	for index, key := range cfg.APIKeys {
		fingerprint, err := g.store.Fingerprint("token:"+sdkaccess.DefaultAccessProviderName, strings.TrimSpace(key))
		if err != nil {
			return
		}
		if id := byFingerprint[fingerprint]; id != "" {
			catalog[id] = groupingadmin.Label{Label: fmt.Sprintf("API key #%d", index+1), Source: fmt.Sprintf("config.yaml · api-keys[%d]", index)}
		}
	}
	g.catalog = catalog
}

func groupingDisplayText(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}
