package config

import internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"

// GroupingConfig configures local credential and API token access groups.
type GroupingConfig = internalconfig.GroupingConfig

// ValidateGroupingMode rejects unsupported combinations of deployment modes.
func ValidateGroupingMode(cfg *Config) error {
	return internalconfig.ValidateGroupingMode(cfg)
}

// EnsureGroupingCredentialIDs initializes missing source UUIDs only when explicitly
// called. It does not persist configuration or enable grouping.
func EnsureGroupingCredentialIDs(cfg *Config) (bool, error) {
	return internalconfig.EnsureGroupingCredentialIDs(cfg)
}

// ValidateGroupingCredentialIDs checks existing source identities without mutation.
func ValidateGroupingCredentialIDs(cfg *Config) error {
	return internalconfig.ValidateGroupingCredentialIDs(cfg)
}

// GroupingCredentialSources maps persistent IDs to nonsecret configuration paths.
func GroupingCredentialSources(cfg *Config) map[string]string {
	return internalconfig.GroupingCredentialSources(cfg)
}

// PrepareGroupingConfigDocument preserves the document while filling source IDs.
func PrepareGroupingConfigDocument(data []byte, cfg *Config) ([]byte, error) {
	return internalconfig.PrepareGroupingConfigDocument(data, cfg)
}
