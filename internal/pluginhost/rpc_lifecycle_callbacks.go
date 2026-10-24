package pluginhost

import (
	"bytes"
	"context"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

func callPluginLifecycle(ctx context.Context, host *Host, id string, client pluginClient, method string, configYAML []byte) (rpcRegistration, error) {
	if method != pluginabi.MethodPluginRegister && method != pluginabi.MethodPluginReconfigure {
		return rpcRegistration{}, fmt.Errorf("unsupported plugin lifecycle method %s", method)
	}
	// Only the host's lifecycle boundary can issue this maintenance scope. It is
	// bound to the current client instance and expires when the lifecycle call ends.
	ctx = access.WithInternalOperation(ctx, access.InternalMaintenance)
	instance := pluginCallbackInstance(client)
	maintenanceID, errMaintenance := host.issueMaintenanceCallback(id, instance, configYAML)
	if errMaintenance != nil {
		return rpcRegistration{}, errMaintenance
	}
	completed := false
	defer func() {
		if !completed {
			instance.revokeMaintenanceCallback()
		}
	}()
	callbackID, closeCallback := host.openCallbackContextForPluginInstance(ctx, id, instance)
	defer closeCallback()
	adapter := &rpcPluginAdapter{id: id, host: host, client: client, instance: instance}
	response, errCall := callPluginWithAccess[rpcRegistration](ctx, adapter, method, rpcLifecycleRequest{
		ConfigYAML: bytes.Clone(configYAML), SchemaVersion: pluginabi.SchemaVersion,
		HostCallbackID: callbackID, MaintenanceCallbackID: maintenanceID,
	}, callbackID)
	completed = errCall == nil
	return response, errCall
}
