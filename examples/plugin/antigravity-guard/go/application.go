package main

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type application struct {
	host       hostClient
	store      *stateStore
	guard      *guard
	quota      *quotaService
	auth       *authService
	proxies    *proxyCatalog
	configMu   sync.RWMutex
	config     guardConfig
	baseConfig guardConfig
	baseSet    bool
	shutdownMu sync.Once
}

func newApplication(host hostClient) *application {
	defaultConfig, errConfig := normalizeConfig(defaultPluginConfig())
	if errConfig != nil {
		panic(errConfig)
	}
	app := &application{host: host, store: newStateStore(), config: defaultConfig, proxies: newProxyCatalog()}
	app.quota = newQuotaService(host, app.store, app.loadedConfig)
	app.guard = newGuard(host, app.store, app.loadedConfig, app.quota)
	app.auth = newAuthService(host, app.store, app.loadedConfig, app.proxies)
	app.guard.start()
	return app
}

func (a *application) handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := a.configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(a.registration())
	case pluginabi.MethodUsageHandle:
		return a.handleUsage(request)
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRoutes())
	case pluginabi.MethodManagementHandle:
		return a.handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func (a *application) configure(raw []byte) error {
	var request lifecycleRequest
	if len(raw) > 0 {
		if errDecode := json.Unmarshal(raw, &request); errDecode != nil {
			return fmt.Errorf("decode lifecycle request: %w", errDecode)
		}
	}
	config, errConfig := decodeConfig(request.ConfigYAML)
	if errConfig != nil {
		return errConfig
	}
	a.guard.operations.Lock()
	defer a.guard.operations.Unlock()

	a.configMu.Lock()
	if a.baseSet && guardConfigsEqual(a.baseConfig, config) {
		a.configMu.Unlock()
		return nil
	}
	previous := a.config
	a.baseConfig = config
	a.baseSet = true
	a.config = config
	a.configMu.Unlock()
	if previous.Enabled && !config.Enabled {
		_ = a.guard.clearAutomaticOverridesLocked()
		a.guard.clearManagedProxiesLocked()
	} else if previous.Auto429Enabled && !config.Auto429Enabled {
		_ = a.guard.clearAutomaticOverridesLocked()
	}
	if (!previous.Enabled && config.Enabled) || (!previous.Auto429Enabled && config.Auto429Enabled) {
		a.store.resetAllConsecutive429()
	}
	return nil
}

func (a *application) loadedConfig() guardConfig {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	config := a.config
	config.QuotaURLs = append([]string(nil), config.QuotaURLs...)
	return config
}

func (a *application) handleUsage(raw []byte) ([]byte, error) {
	var record pluginapi.UsageRecord
	if errDecode := json.Unmarshal(raw, &record); errDecode != nil {
		return nil, fmt.Errorf("decode usage record: %w", errDecode)
	}
	a.guard.handleUsage(record)
	return okEnvelope(struct{}{})
}

func (a *application) registration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginID,
			Version:          "0.1.0",
			Author:           "router-for-me",
			GitHubRepository: "https://github.com/router-for-me/CLIProxyAPI",
			Logo:             "https://raw.githubusercontent.com/router-for-me/CLIProxyAPI/main/docs/logo.png",
			ConfigFields:     configFields(),
		},
		Capabilities: registrationCapabilities{UsagePlugin: true, ManagementAPI: true},
	}
}

func configFields() []pluginapi.ConfigField {
	return []pluginapi.ConfigField{
		{Name: "auto_429_enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Enable automatic Antigravity 429 and Codex usage-limit protection while keeping quota and proxy management available."},
		{Name: "action", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{actionDisable, actionPriority}, Description: "Runtime action applied while a credential is cooling down."},
		{Name: "temporary_priority", Type: pluginapi.ConfigFieldTypeInteger, Description: "Effective priority used by priority cooldowns and weekly-quota quarantine."},
		{Name: "consecutive_429_threshold", Type: pluginapi.ConfigFieldTypeInteger, Description: "Consecutive 429 responses required before checking weekly quota and applying a cooldown action."},
		{Name: "generic_require_retry", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Require a Retry time for generic 429 cooldown."},
		{Name: "fallback_cooldown", Type: pluginapi.ConfigFieldTypeString, Description: "Fallback Go duration when quota 429 has no Retry time."},
		{Name: "recent_window", Type: pluginapi.ConfigFieldTypeString, Description: "Window used by the recent activity summary."},
		{Name: "restore_retry", Type: pluginapi.ConfigFieldTypeString, Description: "Retry interval when clearing a runtime override fails."},
		{Name: "weekly_group", Type: pluginapi.ConfigFieldTypeString, Description: "Quota group slug; defaults to gemini-models, while an explicit empty value checks every weekly bucket."},
		{Name: "weekly_empty_threshold", Type: pluginapi.ConfigFieldTypeNumber, Description: "Remaining fraction treated as empty."},
		{Name: "quota_urls", Type: pluginapi.ConfigFieldTypeArray, Description: "Antigravity quota summary endpoints tried in order."},
		{Name: "quota_user_agent", Type: pluginapi.ConfigFieldTypeString, Description: "User-Agent used for quota requests."},
	}
}

func (a *application) shutdown() {
	a.shutdownMu.Do(func() {
		a.guard.shutdown()
	})
}

func okEnvelope(value any) ([]byte, error) {
	raw, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}
