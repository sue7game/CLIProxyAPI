package pluginhost

import (
	"encoding/json"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func hostAuthTokenValue(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if value := hostAuthTokenFromMetadata(auth.Metadata); value != "" {
		return value
	}
	if auth.Attributes != nil {
		return strings.TrimSpace(auth.Attributes["api_key"])
	}
	return ""
}

func hostAntigravityTokenValue(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if value := hostAuthMetadataString(auth.Metadata, "access_token"); value != "" {
		return value
	}
	return hostAuthTokenValue(auth)
}

func hostAuthTokenFromMetadata(metadata map[string]any) string {
	if len(metadata) == 0 {
		return ""
	}
	for _, key := range []string{"accessToken", "access_token"} {
		if value := hostAuthMetadataString(metadata, key); value != "" {
			return value
		}
	}
	switch token := metadata["token"].(type) {
	case string:
		if value := strings.TrimSpace(token); value != "" {
			return value
		}
	case map[string]any:
		for _, key := range []string{"access_token", "accessToken"} {
			if value, ok := token[key].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	case map[string]string:
		for _, key := range []string{"access_token", "accessToken"} {
			if value := strings.TrimSpace(token[key]); value != "" {
				return value
			}
		}
	}
	for _, key := range []string{"id_token", "cookie"} {
		if value := hostAuthMetadataString(metadata, key); value != "" {
			return value
		}
	}
	return ""
}

func hostAntigravityTokenNeedsRefresh(metadata map[string]any, now time.Time) bool {
	const refreshSkew = 30 * time.Second
	if len(metadata) == 0 {
		return true
	}
	if expired := hostAuthMetadataString(metadata, "expired"); expired != "" {
		if timestamp, errParse := time.Parse(time.RFC3339, expired); errParse == nil {
			return !timestamp.After(now.Add(refreshSkew))
		}
	}
	expiresIn := hostAuthMetadataInt64(metadata["expires_in"])
	timestampMilliseconds := hostAuthMetadataInt64(metadata["timestamp"])
	if expiresIn > 0 && timestampMilliseconds > 0 {
		expiresAt := time.UnixMilli(timestampMilliseconds).Add(time.Duration(expiresIn) * time.Second)
		return !expiresAt.After(now.Add(refreshSkew))
	}
	return true
}

func hostAuthMetadataString(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func hostAuthMetadataInt64(raw any) int64 {
	switch value := raw.(type) {
	case int:
		return int64(value)
	case int32:
		return int64(value)
	case int64:
		return value
	case uint:
		return int64(value)
	case uint32:
		return int64(value)
	case uint64:
		if value <= uint64(^uint64(0)>>1) {
			return int64(value)
		}
	case float32:
		return int64(value)
	case float64:
		return int64(value)
	case json.Number:
		parsed, _ := value.Int64()
		return parsed
	case string:
		parsed, _ := json.Number(strings.TrimSpace(value)).Int64()
		return parsed
	}
	return 0
}
