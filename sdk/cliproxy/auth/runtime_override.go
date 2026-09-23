package auth

import (
	"strconv"
	"strings"
)

// RuntimeAuthOverride contains routing-only changes that live for the current
// process lifetime. Pointer fields distinguish an active override from the
// credential's configured value.
type RuntimeAuthOverride struct {
	Disabled *bool   `json:"disabled,omitempty"`
	Priority *int    `json:"priority,omitempty"`
	ProxyURL *string `json:"proxy_url,omitempty"`
}

// RuntimeAuthOverrideField identifies one field that can be cleared without
// disturbing the other active runtime overrides.
type RuntimeAuthOverrideField string

const (
	RuntimeAuthOverrideDisabled RuntimeAuthOverrideField = "disabled"
	RuntimeAuthOverridePriority RuntimeAuthOverrideField = "priority"
	RuntimeAuthOverrideProxyURL RuntimeAuthOverrideField = "proxy_url"
)

// Clone returns an independent copy of the override.
func (o RuntimeAuthOverride) Clone() RuntimeAuthOverride {
	cloned := RuntimeAuthOverride{}
	if o.Disabled != nil {
		value := *o.Disabled
		cloned.Disabled = &value
	}
	if o.Priority != nil {
		value := *o.Priority
		cloned.Priority = &value
	}
	if o.ProxyURL != nil {
		value := *o.ProxyURL
		cloned.ProxyURL = &value
	}
	return cloned
}

// Empty reports whether the override contains no active fields.
func (o RuntimeAuthOverride) Empty() bool {
	return o.Disabled == nil && o.Priority == nil && o.ProxyURL == nil
}

// RuntimeAuthOverride returns a copy of the auth's active routing override.
func (a *Auth) RuntimeAuthOverride() RuntimeAuthOverride {
	if a == nil {
		return RuntimeAuthOverride{}
	}
	return a.runtimeOverride.Clone()
}

// EffectiveDisabled reports whether the credential is disabled by its stored
// configuration, lifecycle status, or a runtime-only override.
func (a *Auth) EffectiveDisabled() bool {
	if a == nil {
		return true
	}
	if a.Disabled || a.Status == StatusDisabled {
		return true
	}
	return a.runtimeDisabled()
}

func (a *Auth) runtimeDisabled() bool {
	return a != nil && a.runtimeOverride.Disabled != nil && *a.runtimeOverride.Disabled
}

// ConfiguredPriority returns the priority stored in the auth attributes.
func (a *Auth) ConfiguredPriority() int {
	if a == nil || a.Attributes == nil {
		return 0
	}
	raw := strings.TrimSpace(a.Attributes["priority"])
	if raw == "" {
		return 0
	}
	priority, errParse := strconv.Atoi(raw)
	if errParse != nil {
		return 0
	}
	return priority
}

// EffectivePriority returns the runtime priority override when present, or the
// configured credential priority otherwise.
func (a *Auth) EffectivePriority() int {
	if a == nil {
		return 0
	}
	if a.runtimeOverride.Priority != nil {
		return *a.runtimeOverride.Priority
	}
	return a.ConfiguredPriority()
}

// EffectiveProxyURL returns the runtime proxy override when present, or the
// proxy configured on the credential otherwise.
func (a *Auth) EffectiveProxyURL() string {
	if a == nil {
		return ""
	}
	if a.runtimeOverride.ProxyURL != nil {
		return *a.runtimeOverride.ProxyURL
	}
	return a.ProxyURL
}

// SetRuntimeAuthOverride merges non-nil override fields into one credential's
// in-memory routing state. It never persists the auth or clears cooldown data.
func (m *Manager) SetRuntimeAuthOverride(authIndex string, override RuntimeAuthOverride) (*Auth, error) {
	auth, _, _, errPatch := m.patchRuntimeAuthOverride(authIndex, false, nil, override, "", nil, nil)
	return auth, errPatch
}

// ClearRuntimeAuthOverride clears selected fields from one credential's
// in-memory routing state. Passing no fields clears the entire override.
func (m *Manager) ClearRuntimeAuthOverride(authIndex string, fields ...RuntimeAuthOverrideField) (*Auth, error) {
	auth, _, _, errPatch := m.patchRuntimeAuthOverride(authIndex, true, fields, RuntimeAuthOverride{}, "", nil, nil)
	return auth, errPatch
}

// PatchRuntimeAuthOverride atomically clears selected fields and applies new
// in-memory routing overrides. An empty clear list leaves existing fields intact.
func (m *Manager) PatchRuntimeAuthOverride(authIndex string, clearFields []RuntimeAuthOverrideField, override RuntimeAuthOverride) (*Auth, error) {
	auth, _, _, errPatch := m.patchRuntimeAuthOverride(authIndex, len(clearFields) > 0, clearFields, override, "", nil, nil)
	return auth, errPatch
}

// PatchRuntimeAuthOverrideIfRevision atomically changes a runtime override only
// when ifRevision matches the current revision of ifRevisionField. A nil
// revision applies unconditionally. A mismatch returns the current auth
// snapshot and revisions with applied=false and does not mutate routing state.
func (m *Manager) PatchRuntimeAuthOverrideIfRevision(
	authIndex string,
	clearFields []RuntimeAuthOverrideField,
	override RuntimeAuthOverride,
	ifRevisionField RuntimeAuthOverrideField,
	ifRevision *uint64,
) (auth *Auth, revisions RuntimeAuthOverrideRevisions, applied bool, err error) {
	return m.patchRuntimeAuthOverride(authIndex, len(clearFields) > 0, clearFields, override, ifRevisionField, ifRevision, nil)
}

// PatchRuntimeAuthOverrideIfRevisions atomically changes a runtime override
// only when every field changed by the patch matches its expected revision.
// A mismatch returns the current auth snapshot and revisions with applied=false
// and does not mutate any runtime routing field.
func (m *Manager) PatchRuntimeAuthOverrideIfRevisions(
	authIndex string,
	clearFields []RuntimeAuthOverrideField,
	override RuntimeAuthOverride,
	ifRevisions RuntimeAuthOverrideRevisions,
) (auth *Auth, revisions RuntimeAuthOverrideRevisions, applied bool, err error) {
	return m.patchRuntimeAuthOverride(authIndex, len(clearFields) > 0, clearFields, override, "", nil, &ifRevisions)
}

func (m *Manager) patchRuntimeAuthOverride(
	authIndex string,
	clearRequested bool,
	clearFields []RuntimeAuthOverrideField,
	override RuntimeAuthOverride,
	ifRevisionField RuntimeAuthOverrideField,
	ifRevision *uint64,
	ifRevisions *RuntimeAuthOverrideRevisions,
) (*Auth, RuntimeAuthOverrideRevisions, bool, error) {
	if m == nil {
		return nil, RuntimeAuthOverrideRevisions{}, false, &Error{Code: "auth_manager_unavailable", Message: "auth manager is unavailable"}
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return nil, RuntimeAuthOverrideRevisions{}, false, &Error{Code: "invalid_auth_index", Message: "auth index is required"}
	}
	patch, errPrepare := prepareRuntimeAuthOverridePatch(
		clearRequested,
		clearFields,
		override,
		ifRevisionField,
		ifRevision,
		ifRevisions,
	)
	if errPrepare != nil {
		return nil, RuntimeAuthOverrideRevisions{}, false, errPrepare
	}
	return m.applyRuntimeAuthOverridePatch(authIndex, patch)
}

func (m *Manager) applyRuntimeAuthOverridePatch(
	authIndex string,
	patch runtimeAuthOverridePatch,
) (*Auth, RuntimeAuthOverrideRevisions, bool, error) {
	m.mu.Lock()
	result, errPatch := m.patchRuntimeAuthOverrideLocked(authIndex, patch)
	m.mu.Unlock()
	if errPatch != nil || !result.applied {
		return result.auth, result.revisions, result.applied, errPatch
	}
	m.syncSchedulerAuth(result.authID)
	if result.affinityChanged {
		m.invalidateSessionAffinity(result.authID)
	}
	return result.auth, result.revisions, true, nil
}

func (m *Manager) patchRuntimeAuthOverrideLocked(
	authIndex string,
	patch runtimeAuthOverridePatch,
) (runtimeAuthOverridePatchResult, error) {
	auth := m.authByIndexLocked(authIndex)
	if auth == nil {
		return runtimeAuthOverridePatchResult{}, &Error{Code: "auth_not_found", Message: "auth index was not found"}
	}
	revisions := m.attachRuntimeAuthOverrideRevisionsLocked(auth)
	if patch.ifRevision != nil && *patch.ifRevision != revisions.Revision(patch.ifRevisionField) {
		return runtimeAuthOverridePatchResult{auth: auth.Clone(), revisions: revisions}, nil
	}
	if patch.ifRevisions != nil && !runtimeAuthOverrideRevisionsMatch(revisions, *patch.ifRevisions, patch.touchedFields) {
		return runtimeAuthOverridePatchResult{auth: auth.Clone(), revisions: revisions}, nil
	}
	if errRevision := ensureRuntimeAuthOverrideRevisionsAvailable(revisions, patch.touchedFields); errRevision != nil {
		return runtimeAuthOverridePatchResult{revisions: revisions}, errRevision
	}
	previousDisabled := auth.EffectiveDisabled()
	previousPriority := auth.EffectivePriority()
	if patch.clearRequested {
		clearRuntimeAuthOverride(&auth.runtimeOverride, patch.clearFields)
	}
	if !patch.override.Empty() {
		mergeRuntimeAuthOverride(&auth.runtimeOverride, patch.override)
	}
	for _, field := range patch.touchedFields {
		advanceRuntimeAuthOverrideRevision(&revisions, field)
	}
	auth.runtimeOverrideRevisions = revisions
	m.runtimeAuthOverrideRevisions[authIndex] = revisions
	// Fence delayed lifecycle, result and rebuild snapshots in the native scheduler.
	auth.Generation++
	return runtimeAuthOverridePatchResult{
		auth:            auth.Clone(),
		revisions:       revisions,
		applied:         true,
		authID:          auth.ID,
		affinityChanged: previousDisabled != auth.EffectiveDisabled() || previousPriority != auth.EffectivePriority(),
	}, nil
}

// GetRuntimeAuthOverride returns a copy of one credential's runtime override.
// The boolean reports whether the auth index exists, even when no fields are set.
func (m *Manager) GetRuntimeAuthOverride(authIndex string) (RuntimeAuthOverride, bool) {
	if m == nil {
		return RuntimeAuthOverride{}, false
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return RuntimeAuthOverride{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	auth := m.authByIndexReadLocked(authIndex)
	if auth == nil {
		return RuntimeAuthOverride{}, false
	}
	return auth.runtimeOverride.Clone(), true
}

func normalizeRuntimeAuthOverride(override RuntimeAuthOverride) (RuntimeAuthOverride, error) {
	if override.Empty() {
		return RuntimeAuthOverride{}, &Error{Code: "invalid_runtime_override", Message: "at least one runtime override field is required"}
	}
	normalized := override.Clone()
	if normalized.Disabled != nil && !*normalized.Disabled {
		return RuntimeAuthOverride{}, &Error{Code: "invalid_runtime_override", Message: "clear the disabled override instead of setting it to false"}
	}
	if normalized.ProxyURL != nil {
		proxyURL := strings.TrimSpace(*normalized.ProxyURL)
		if proxyURL == "" {
			return RuntimeAuthOverride{}, &Error{Code: "invalid_runtime_override", Message: "proxy_url cannot be empty; clear it to restore the configured proxy"}
		}
		normalized.ProxyURL = &proxyURL
	}
	return normalized, nil
}

func mergeRuntimeAuthOverride(current *RuntimeAuthOverride, next RuntimeAuthOverride) {
	if current == nil {
		return
	}
	if next.Disabled != nil {
		value := *next.Disabled
		current.Disabled = &value
	}
	if next.Priority != nil {
		value := *next.Priority
		current.Priority = &value
	}
	if next.ProxyURL != nil {
		value := *next.ProxyURL
		current.ProxyURL = &value
	}
}

func validateRuntimeAuthOverrideFields(fields []RuntimeAuthOverrideField) error {
	for _, field := range fields {
		switch field {
		case RuntimeAuthOverrideDisabled, RuntimeAuthOverridePriority, RuntimeAuthOverrideProxyURL:
		default:
			return &Error{Code: "invalid_runtime_override", Message: "unknown runtime override field: " + string(field)}
		}
	}
	return nil
}

func clearRuntimeAuthOverride(current *RuntimeAuthOverride, fields []RuntimeAuthOverrideField) {
	if current == nil {
		return
	}
	if len(fields) == 0 {
		*current = RuntimeAuthOverride{}
		return
	}
	for _, field := range fields {
		switch field {
		case RuntimeAuthOverrideDisabled:
			current.Disabled = nil
		case RuntimeAuthOverridePriority:
			current.Priority = nil
		case RuntimeAuthOverrideProxyURL:
			current.ProxyURL = nil
		}
	}
}

func (m *Manager) authByIndexLocked(authIndex string) *Auth {
	for _, auth := range m.auths {
		if auth == nil {
			continue
		}
		if auth.Index == "" {
			auth.EnsureIndex()
		}
		if strings.TrimSpace(auth.Index) == authIndex {
			return auth
		}
	}
	return nil
}

func (m *Manager) authByIndexReadLocked(authIndex string) *Auth {
	for _, auth := range m.auths {
		if auth != nil && strings.TrimSpace(auth.Index) == authIndex {
			return auth
		}
	}
	return nil
}
