# Grouping management additions

All endpoints remain under the existing authenticated management route group.
The backend interface and existing mutation request bodies remain unchanged.
These additions do not change registration defaults or the meaning of `all` in
authorization. Newly registered objects without an explicit group still use `all`.

## Identity list queries

`GET /credentials` and `GET /tokens` accept only:

- `filter_mode`: `actual` (default) or `accessible`. Tokens accept only `actual`.
  `accessible` is credentials-only, requires `group_id`, and includes only active
  credentials eligible under the grouping rules: `all` can access every active
  credential; a concrete group can access its own and `all` credentials.
- `group_id`: `all` or a canonical, nonzero, lowercase group UUID. In `actual`
  mode, `group_id=all` returns only identities assigned to `all`; omitting the
  parameter includes every membership. In `accessible` mode it identifies the
  hypothetical token's group, not an actual token or an authorization bypass.
  A syntactically valid but absent group UUID returns an empty list in either
  mode, without a separate group-catalog read.
- `limit`: a canonical decimal integer from 1 through 500.
- `offset`: a canonical nonnegative decimal integer; requires `limit`, defaults
  to zero when `limit` is present. Offsets beyond the end return `items: []`.

Unknown, duplicated, empty, malformed, or noncanonical parameters return 400.
The `actual` filter includes active, pending, and retired identities, as the
original list did. Query results sort by logical ID before slicing, not by labels.
With `limit`, the response adds
`pagination: {"total": <filtered count>, "offset": <requested offset>, "limit": <requested limit>}`.
Filtering, totals, and slicing operate on one backend snapshot; ETag and
`revision` identify that snapshot. Multiple pages are independent reads: clients
must restart pagination if revisions differ. Without a query the original list
behavior and response shape are unchanged. Group-only filters add no pagination
metadata. Accessible filtering uses the backend's complete `ItemsResult.GroupIDs`
from that same snapshot; this internal field is not serialized. Missing or invalid
group metadata fails with 503 rather than broadening access. Custom backends must
provide it to support this mode; the built-in backend already does.

## Binding preview

`POST /preview` preserves `revision` and `affected_count` and adds:

- `permission_expansion`: exactly the confirmation predicate used by `Apply`.
  Moving a changed identity to `all` requires confirmation even when there are
  no additional current access edges, because the wildcard applies to future
  registrations too. Providing confirmation in a preview does not suppress this
  flag, and preview never requires confirmation or writes state.
- `credential_access_changes`: logical-token-ID-sorted entries for active tokens
  gaining or losing group-policy eligibility, including tokens not selected in
  the request. Each entry contains `token_id`, `before_count`, `after_count`,
  `added_count`, and `removed_count`. Counts refer to distinct active logical
  credential IDs; identical source secrets do not merge identities. Added and
  removed are set differences, so both may be positive when totals are equal.
  An empty array means no current credential eligibility changes.

These credential fields are exact **group-policy** results from the same locked snapshot used to
validate the proposed batch. They do not predict disabled-provider, quota,
health, routing, or model availability. Pending and retired identities do not
contribute to eligible sets. The calculation aggregates credential groups rather
than building a token/credential cross product.

### Registered-model preview

The preview also always includes `models_available`, `models_scope`, and
`model_access_changes`. The scope is the literal `registered_model_catalog`:
registered public model IDs under group policy, not predictions of quota,
cooldown, provider health, or actual traffic outcomes.

When available, `models_available` is true and `model_access_changes` is an array
of changed active token model unions, sorted by `token_id`. Each entry contains
`token_id`, `before`, `after`, `added`, and `removed`. All four model-ID lists are
sorted, deduplicated arrays, including `[]` for empty sets. Only changed unions
appear; unchanged unions are omitted even if credential access changed. Tokens
not selected in the batch are included when their model union changes. Multiple
eligible credentials advertising the same public ID contribute one model, not
multiple models; losing one of those credentials need not remove the model.

When unavailable, `models_available` is false, `model_access_changes` is **null**,
and `models_unavailable_reason` is `not_configured` (missing callback) or
`catalog_unavailable` (callback error, nil catalog, or invalid public model ID).
Raw callback errors are never exposed. The credential preview remains available.
An unavailable model preview is never reported as an empty successful diff.
Successful catalog reads with no model changes return `[]` and omit the reason.
Model availability and model differences do not alter `permission_expansion`.

Service must wire the implemented `groupingadmin.Options.ModelCatalog` callback:

```go
func(context.Context, grouping.Snapshot) (map[string][]string, error)
```

It runs **once** per valid preview under the shared lock with an isolated copy of
the original snapshot, never the hypothetical updated policy. The backend uses
this one catalog for both before/after unions, aggregates by credential group,
and does not request a token/credential cross product from Service. Keys are
stable credential UUIDs; values are public registered model IDs with alias,
prefix, and disabled-source handling already applied by Service. The callback
must use the current in-memory directory, perform no upstream I/O, and not
reacquire the shared lock. Production Service integrations must provide it.

Omitted credentials have no registered models; a non-nil empty map is an
authoritative empty directory. Catalog entries for unknown identities, tokens,
pending credentials, or retired credentials do not grant model access. Active
credential model IDs must be nonempty UTF-8 strings without surrounding whitespace
or control characters; IDs are not trimmed, normalized, or translated here.

## Mutation audit

The real backend logs every `Initialize`/`Apply` success and failure through
logrus. The HTTP adapter logs validation/unavailable-backend rejections before
delegation, but does not duplicate backend events. Parent authentication rejects
requests before these routes and remains the parent's audit responsibility.

Fields are allowlisted: `action`, `namespace`, `revision`, `logical_ids`,
`group_changes` (`id`, `old_group`, `new_group`), and `confirmation_reason`.
Success/failure uses fixed messages and Info/Warn levels. No names, raw errors,
secrets, request bodies, authentication headers, or fingerprints are logged.
Confirmation reasons are fixed codes (`permission_expansion`, `disable_grouping`,
`identity_rebind`), emitted only when the relevant explicit confirmation is
present; free-text reasons are not accepted or logged.

Success uses the applied revision; failure uses the requested CAS revision.
Initialization failure or rejected unvalidated requests use revision zero.
Unavailable namespaces are omitted. Failed group changes describe an attempted
assignment, not a completed one. Old groups are recorded only from the requested
base revision; stale requests never borrow relationships from a newer snapshot.

Ordinary mutations capture audit data under the shared transaction lock.
Lifecycle callbacks retain ownership of their locks, CAS, source verification,
and consent checks. Their audit base is sampled under the same shared lock before
delegation and is usable only when its revision matches the requested CAS.
Successful callbacks must preserve installation namespace, never reuse revisions,
and preserve ID/group during rebind, as required by `groupingadmin.Options`.
The adapter does not widen authorization to obtain audit metadata.

These are operational logs, **not an independent durable audit ledger**: log
level, sinks, retention, process crashes, and sink failures affect delivery.
Custom backend implementations retain responsibility for their own audit events.
