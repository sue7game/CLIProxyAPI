# Native plugin callback scopes

The host includes two optional identifiers in `plugin.register` and
`plugin.reconfigure` lifecycle requests:

- `host_callback_id` is a short-lived host maintenance scope. Use it only for
  synchronous initialization or cleanup during that lifecycle call. It expires
  when the call returns, including on failure or cancellation.
- `maintenance_callback_id` is a separate host-issued background maintenance
  capability for an enabled native plugin instance. It is not a client identity
  and must never replace the callback identifier of a management, frontend-auth,
  executor, or other client request.

Pass the selected identifier as `host_callback_id` in host callbacks. Background
maintenance allows only `host.auth.list`, `host.auth.get`,
`host.auth.get_runtime`, `host.auth.request`, and
`host.auth.set_runtime_override`. Model execution, raw HTTP, auth-file writes,
routing changes, and other host methods cannot use that capability.

Both scopes are random and bound to the calling plugin instance. The host revokes
background maintenance before disable, replacement cleanup, unload, or failed
registration. Reconfiguration and rollback issue a new identifier; never retain
an old one as fallback. Revocation also cancels associated HTTP operations.

Trusted maintenance can enumerate disabled credential metadata to restore
plugin-owned overrides. This does not authorize network use of disabled
credentials: `host.auth.request` still checks credential policy before token
resolution and before every upstream request, including redirects.

Native plugins are operator-trusted code, not a sandbox for hostile binaries.
Store maintenance capability separately from per-request callback scope. A
missing, expired, or rejected request scope must fail rather than retry with
maintenance privileges. External request data cannot mint a trusted scope.
