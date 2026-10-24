package main

func (c *hostRPCClient) requestCallbackID(id string) string {
	if c.callbackID != nil {
		return *c.callbackID
	}
	if id != "" {
		return id
	}
	return c.hostCallbackID()
}

func (c *hostRPCClient) hostCallbackID() string {
	if c.callbackID != nil {
		return *c.callbackID
	}
	if id := c.maintenance.Load(); id != nil {
		return *id
	}
	return ""
}

func (c *hostRPCClient) withCallback(id string) hostClient {
	return &hostRPCClient{maintenance: c.maintenance, callbackID: &id, transport: c.transport}
}

func (c *hostRPCClient) setMaintenanceCallback(id string) {
	c.maintenance.Store(&id)
}

func scopedHostClient(host hostClient, ids ...string) hostClient {
	id := ""
	if len(ids) > 0 {
		id = ids[0]
	}
	if scoped, ok := host.(interface{ withCallback(string) hostClient }); ok {
		return scoped.withCallback(id)
	}
	return host
}

func setMaintenanceCallback(host hostClient, id string) {
	if scoped, ok := host.(interface{ setMaintenanceCallback(string) }); ok {
		scoped.setMaintenanceCallback(id)
	}
}

// useHostLocked scopes one serialized guard operation without changing background identity.
func (g *guard) useHostLocked(host hostClient) func() {
	previous := g.operationHost
	g.operationHost = host
	return func() { g.operationHost = previous }
}

func (g *guard) currentHostLocked() hostClient {
	if g.operationHost != nil {
		return g.operationHost
	}
	return g.host
}
