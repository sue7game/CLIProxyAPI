package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"gopkg.in/yaml.v3"
)

type maintenanceCallbackKey struct{}

func (h *Host) revokePluginMaintenance(pluginID string) {
	h.mu.Lock()
	var instances []*hostCallbackInstance
	if loaded := h.loaded[pluginID]; loaded != nil {
		instances = append(instances, loaded.callbackInstance)
	}
	for _, retired := range h.retired[pluginID] {
		instances = append(instances, retired.callbackInstance)
	}
	if loading := h.loading[pluginID]; loading != nil {
		for instance := range loading.callbackInstances {
			instances = append(instances, instance)
		}
	}
	h.mu.Unlock()
	for _, instance := range instances {
		instance.revokeMaintenanceCallback()
	}
}

func (instance *hostCallbackInstance) revokeMaintenanceCallback() {
	if instance == nil {
		return
	}
	instance.maintenanceMu.Lock()
	closeCallback := instance.maintenanceClose
	instance.maintenanceClose = nil
	instance.maintenanceMu.Unlock()
	if closeCallback != nil {
		closeCallback()
	}
}

func (h *Host) issueMaintenanceCallback(pluginID string, instance *hostCallbackInstance, configYAML []byte) (string, error) {
	if instance == nil {
		return "", nil
	}
	instance.revokeMaintenanceCallback()
	if h == nil {
		return "", nil
	}
	var config struct {
		Enabled bool `yaml:"enabled"`
	}
	if errDecode := yaml.Unmarshal(configYAML, &config); errDecode != nil {
		return "", fmt.Errorf("decode host lifecycle enablement: %w", errDecode)
	}
	if !config.Enabled {
		return "", nil
	}
	return h.openMaintenanceCallback(pluginID, instance)
}

func (h *Host) openMaintenanceCallback(pluginID string, instance *hostCallbackInstance) (string, error) {
	instance.maintenanceMu.Lock()
	defer instance.maintenanceMu.Unlock()
	if instance.closed.Load() {
		return "", fmt.Errorf("plugin callback instance is closed")
	}
	// This host-issued capability belongs only to the enabled native instance.
	// It is not derived from client metadata or a missing request identity.
	ctx, cancel := context.WithCancel(access.WithInternalOperation(context.Background(), access.InternalMaintenance))
	ctx = context.WithValue(ctx, maintenanceCallbackKey{}, true)
	id, closeCallback := h.openCallbackContextForPluginInstance(ctx, pluginID, instance)
	if id == "" {
		cancel()
		return "", fmt.Errorf("maintenance callback registry is unavailable")
	}
	instance.maintenanceClose = func() {
		cancel()
		closeCallback()
	}
	return id, nil
}

func (h *Host) validateMaintenanceCallback(ctx context.Context, method string, request []byte) error {
	var req struct {
		HostCallbackID string `json:"host_callback_id"`
	}
	if json.Unmarshal(request, &req) != nil || strings.TrimSpace(req.HostCallbackID) == "" {
		return nil
	}
	stored, owner, instance, exists := h.lookupCallbackContext(req.HostCallbackID)
	if !exists || stored.Err() != nil {
		return groupingCallbackDenied()
	}
	maintenance, _ := stored.Value(maintenanceCallbackKey{}).(bool)
	if !maintenance {
		return nil
	}
	if owner != hostCallbackPluginIDFromContext(ctx) || instance == nil || instance != hostCallbackInstanceFromContext(ctx) || instance.closed.Load() {
		return groupingCallbackDenied()
	}
	switch method {
	case pluginabi.MethodHostAuthList, pluginabi.MethodHostAuthGet, pluginabi.MethodHostAuthGetRuntime,
		pluginabi.MethodHostAuthRequest, pluginabi.MethodHostAuthSetRuntimeOverride:
		return nil
	default:
		return groupingCallbackDenied()
	}
}
