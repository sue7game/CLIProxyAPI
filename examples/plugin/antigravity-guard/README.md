# Antigravity Guard

`antigravity-guard` is a Go C-ABI plugin for managing Antigravity credentials in one CLIProxyAPI process. It provides automatic 429 protection, manual weekly-quota inspection, and runtime proxy management without rewriting credential JSON files.

## Scope

- Only credentials whose provider is `antigravity` are observed or modified.
- Runtime overrides and proxy aliases are in memory. Restarting CLIProxyAPI starts with no plugin counters, cooldowns, weekly quarantines, quota markers, proxy overrides, or aliases.
- The plugin never persists priority, disabled state, proxy settings, or quota state.
- Home-mode credential dispatch is not supported; the plugin manages credentials routed by the local auth manager.
- The plugin requires the `host.auth.set_runtime_override` and `host.auth.request` callbacks included in this source tree. Build CLIProxyAPI and the plugin from the same revision.

## Features

### Automatic 429 protection

- Ignores usage records with `Generate=false`, so `count_tokens` calls do not reset or trigger the guard.
- Requires consecutive 429 responses before taking action. The default is three and can be changed with `consecutive_429_threshold` in configuration or on the management page. A non-429 generated response resets the counter.
- Treats `QUOTA_EXHAUSTED`, explicit quota messages, and weighted-token exhaustion as quota 429 responses when determining the Retry window.
- Treats `RATE_LIMIT_EXCEEDED` with a Retry window of at least five minutes as quota exhaustion; shorter windows remain ordinary rate limits. Both use the same consecutive threshold.
- Reads Retry information from `Retry-After`, rate-limit reset headers, `retryDelay`, `quotaResetDelay`, `quotaResetTimeStamp`, and related JSON fields.
- After the consecutive threshold is reached, queries the credential's Gemini weekly and five-hour quota windows through its effective proxy before choosing an action. If the weekly quota is empty, the plugin atomically sets `temporary_priority` and disables the credential regardless of the configured action. This weekly quarantine never restores itself; the reset time is used only for the countdown and sorting, and the credential remains quarantined until manual release, guard/plugin shutdown, or process restart. If weekly quota is available but the five-hour window is empty, the configured `disable` or `priority` action is applied until the five-hour reset time and then restored automatically. If both windows are available, normal cooldown rules apply. If the quota query fails, the configured action is used and the error remains visible on the page.
- Can temporarily disable the credential or set an exact runtime priority. Before applying the action, it records the original runtime value for the affected `disabled` or `priority` field.
- When the Retry time expires, it restores the recorded runtime value. If there was no original runtime value, it clears that field so the latest configured value takes effect again.
- The host maintains independent in-memory revisions for `disabled`, `priority`, and `proxy_url`. Normal cooldown writes use a field compare-and-swap; weekly quarantine atomically checks and writes both `disabled` and `priority`. Release restores priority before disabled, with an independent revision check for each field. Even a same-value manual write advances the revision and is treated as `manual_takeover`; unrelated proxy changes do not block priority or disabled restoration.
- Turning automatic protection off immediately attempts to restore every active automatic cooldown and weekly quarantine. Failed restores remain scheduled and are retried at `restore_retry` intervals without persisting state.
- The management page can switch automatic protection, choose `disable` or `priority`, set `temporary_priority`, and change the consecutive 429 threshold for the current process. `temporary_priority` also controls weekly quarantine in both action modes. Existing cooldowns and quarantines keep the values that originally created them.
- Repeated `plugin.reconfigure` events with the same normalized plugin configuration preserve these management-page settings. A real plugin configuration change replaces them with the new configured values; a process restart also starts from configuration again.

Outside weekly quarantine, `action: disable` is the only mode that guarantees the exhausted credential stops receiving new local routing requests. When using `action: priority`, set `temporary_priority` lower than every credential that should be deprioritized; the value is applied exactly and is not calculated from the configured priority. Priority mode redirects traffic only when another compatible credential has a higher effective priority. If no better credential is available, the cooled credential can still be selected.

### Weekly quota marker

The management page fetches quota when **Get quota** is selected for a credential. Automatic 429 protection also performs one quota check when a credential reaches the configured consecutive threshold and does not repeat that check while the credential already has an active or pending cooldown. Both paths use the same Antigravity quota-summary endpoints and request shape as the CLIProxyAPI Management Center.

- All matching weekly buckets must be empty before the credential is marked.
- If any matching weekly bucket still has quota, the page reports that weekly quota is available.
- Whenever the upstream returns `resetTime`, the page shows a live countdown to the minute for both available and exhausted quota. Re-fetching quota replaces the cached reset time and corrects the countdown.
- Credentials with exhausted weekly quota are listed after credentials whose quota is available or unknown, ordered by the soonest known weekly reset time. Exhausted credentials without a known reset time are listed last.
- `weekly_group` defaults to `gemini-models`, so only the Gemini weekly limit controls the marker and automatic forced-disable decision. Set it to an explicit empty string only if every weekly group should be checked together.
- The upstream `Date` header is used to compensate for clock skew.
- A weekly-quarantined empty result is retained after `resetTime` and displays **Refresh time reached** until quota is fetched again or the quarantine is manually released. Other cached quota results expire locally at `resetTime`; expiry never makes another upstream request.

### Runtime proxy management

- Proxy changes take effect immediately through a host runtime override and never rewrite credential JSON; restarting CLIProxyAPI restores configured proxy behavior.
- Groups credentials by effective proxy and shows only the configured credential total and the number currently active or waiting in a five-hour cooldown.
- Assigns each current reusable proxy an opaque `proxy_id` using HMAC-SHA256 and a random process key. The identifier does not expose the proxy URL or password, and it changes after a process restart.
- Supports a human-readable alias for each current reusable Antigravity proxy. Aliases are unique ignoring case, limited to 40 Unicode characters, and stored only for the current process; an empty alias clears it.
- Filters credentials by all, currently in use, available after a weekly refresh, waiting for automatic cooldown recovery, weekly quarantine, or disabled.
- Refreshes dashboard state every 30 seconds without overlapping requests, while pausing when the tab is hidden or another operation is active.
- Moves active credentials with consecutive 429 responses to the front and highlights them. Cooldowns and quarantines sort by recovery time. Disabled credentials whose weekly quota is now available form a separate available group and no longer sort by the next weekly reset; remaining weekly-empty disabled credentials still sort by refresh time.
- Displays only the alias when an effective proxy has one, avoiding duplicate address and source details.
- Supports single or batch runtime proxy changes, forced direct connection with `direct`, and restoration of configured proxy behavior.
- Each credential can copy the currently effective proxy of another Antigravity credential without exposing the original proxy password to the browser.
- Displayed proxy state removes all URL user information, query parameters, and fragments so username-style tokens and URL parameters are not exposed. Successfully applied proxy values are cleared from the input.
- Search ignores case and common separators, and also matches the most recently used model.

## Build

Go 1.26+, CGO, and a working C compiler are required.

```bash
cd examples/plugin/antigravity-guard/go
go test ./...
```

Linux:

```bash
go build -buildmode=c-shared -o antigravity-guard.so .
```

macOS:

```bash
go build -buildmode=c-shared -o antigravity-guard.dylib .
```

The filename must be exactly `antigravity-guard.so`, `antigravity-guard.dylib`, or `antigravity-guard.dll` so the host resolves the plugin ID as `antigravity-guard`. The generated C header is not needed at runtime.

## Install and configure

Copy the dynamic library into `plugins.dir`, then enable the plugin:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    antigravity-guard:
      enabled: true
      priority: 10
      auto_429_enabled: true
      action: disable
      temporary_priority: 13
      consecutive_429_threshold: 3
      generic_require_retry: true
      fallback_cooldown: 5h
      recent_window: 10m
      restore_retry: 15s
      weekly_group: "gemini-models"
      weekly_empty_threshold: 0
      quota_user_agent: "antigravity/cli/1.0.13 (aidev_client; os_type=darwin; arch=arm64)"
```

For migration, the legacy `quota_429_threshold` and `generic_429_threshold` keys are still accepted when `consecutive_429_threshold` is absent; the larger legacy value becomes the unified threshold. The new key takes precedence when present.

`plugins.configs.antigravity-guard.enabled` controls whether the host activates and exposes the plugin. Disabling an already loaded instance deactivates it in place, immediately attempts to restore automatic cooldowns, and safely clears plugin-managed proxy overrides; re-enabling reuses the same instance. `auto_429_enabled` independently controls automatic 429 actions while leaving quota and proxy management available. The host-level `priority` controls plugin ordering; it does not change credential priority.

Optional quota endpoints can be supplied in order:

```yaml
      quota_urls:
        - "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
        - "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:retrieveUserQuotaSummary"
        - "https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
```

Restart CLIProxyAPI after installing or replacing the dynamic library.

## Management page

Open:

```text
/v0/resource/plugins/antigravity-guard/dashboard
```

The page asks for the Management Key and keeps it only in the current tab's `sessionStorage`. Authenticated actions use these Management API routes:

- `GET /v0/management/plugins/antigravity-guard/state`
- `POST /v0/management/plugins/antigravity-guard/settings`
- `POST /v0/management/plugins/antigravity-guard/quota`
- `POST /v0/management/plugins/antigravity-guard/proxy`
- `POST /v0/management/plugins/antigravity-guard/proxy/alias`
- `POST /v0/management/plugins/antigravity-guard/cooldown/clear`

Set or clear an alias with:

```json
{
  "proxy_id": "p_...",
  "alias": "US residential 01"
}
```

`proxy_id` must identify a proxy currently used by an Antigravity credential. Send an empty `alias` to clear the current alias.

Use HTTPS or a trusted local connection when entering a Management Key or a proxy URL containing credentials.

## Security and state boundaries

- The plugin lists runtime credential metadata but does not read full credential JSON or OAuth tokens.
- `$TOKEN$` is replaced by the host only in outbound request headers. The token is not returned to the plugin.
- Every management action revalidates that the target `auth_index` belongs to Antigravity before invoking a host side effect.
- Browser resources are read-only static assets. Mutating operations are exposed only through authenticated Management API routes.
- Disabling automatic 429 protection immediately restores automatic cooldown and weekly-quarantine overrides but keeps manually managed proxy overrides. A failed restore remains visible and is retried according to `restore_retry`.
- Disabling the plugin at the host level removes its routes before sending `enabled: false` through `plugin.reconfigure`. The shared library stays loaded so the same instance can be re-enabled without a process restart. A transient managed-proxy cleanup error is retried according to `restore_retry`.
- Cooldown and quarantine release only revert field revisions written by the guard. A later runtime write, including a same-value write, is treated as manual takeover and is never overwritten.
- Proxy aliases and the process-keyed `proxy_id` values are not persistent and are recreated after restart.
- Graceful plugin shutdown stops the restore loop before clearing automatic cooldown, weekly-quarantine, and proxy overrides. Proxy cleanup also uses compare-and-swap and will not clear a proxy taken over by another operation. The host shuts down the retired instance during plugin hot replacement. A process restart clears all runtime state by design.

## Verification

```bash
cd examples/plugin/antigravity-guard/go
gofmt -w *.go
go test ./...
go build -buildmode=c-shared -o /tmp/antigravity-guard.so .
```
