package auth

import (
	"math"
	"strings"
)

type runtimeAuthOverridePatch struct {
	clearRequested  bool
	clearFields     []RuntimeAuthOverrideField
	override        RuntimeAuthOverride
	touchedFields   []RuntimeAuthOverrideField
	ifRevisionField RuntimeAuthOverrideField
	ifRevision      *uint64
	ifRevisions     *RuntimeAuthOverrideRevisions
}

type runtimeAuthOverridePatchResult struct {
	auth            *Auth
	revisions       RuntimeAuthOverrideRevisions
	applied         bool
	authID          string
	affinityChanged bool
}

// RuntimeAuthOverrideRevisions contains independent fencing revisions for
// runtime routing fields. Updating one field does not invalidate a compare-and-
// swap operation that guards another field.
type RuntimeAuthOverrideRevisions struct {
	Disabled uint64 `json:"disabled"`
	Priority uint64 `json:"priority"`
	ProxyURL uint64 `json:"proxy_url"`
}

// Revision returns the revision for one runtime override field.
func (r RuntimeAuthOverrideRevisions) Revision(field RuntimeAuthOverrideField) uint64 {
	switch field {
	case RuntimeAuthOverrideDisabled:
		return r.Disabled
	case RuntimeAuthOverridePriority:
		return r.Priority
	case RuntimeAuthOverrideProxyURL:
		return r.ProxyURL
	default:
		return 0
	}
}

// RuntimeAuthOverrideRevisions returns process-local field revisions. Every
// successful patch advances each touched field, including same-value writes.
func (a *Auth) RuntimeAuthOverrideRevisions() RuntimeAuthOverrideRevisions {
	if a == nil {
		return RuntimeAuthOverrideRevisions{}
	}
	return a.runtimeOverrideRevisions
}

// GetRuntimeAuthOverrideRevisions returns the current process-local field revisions.
// The boolean reports whether the auth index exists.
func (m *Manager) GetRuntimeAuthOverrideRevisions(authIndex string) (RuntimeAuthOverrideRevisions, bool) {
	if m == nil {
		return RuntimeAuthOverrideRevisions{}, false
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return RuntimeAuthOverrideRevisions{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	auth := m.authByIndexReadLocked(authIndex)
	if auth == nil {
		return RuntimeAuthOverrideRevisions{}, false
	}
	return auth.runtimeOverrideRevisions, true
}

func (m *Manager) attachRuntimeAuthOverrideRevisionsLocked(auth *Auth) RuntimeAuthOverrideRevisions {
	if m == nil || auth == nil {
		return RuntimeAuthOverrideRevisions{}
	}
	auth.EnsureIndex()
	authIndex := strings.TrimSpace(auth.Index)
	if authIndex == "" {
		return auth.runtimeOverrideRevisions
	}
	if m.runtimeAuthOverrideRevisions == nil {
		m.runtimeAuthOverrideRevisions = make(map[string]RuntimeAuthOverrideRevisions)
	}
	revisions := maxRuntimeAuthOverrideRevisions(m.runtimeAuthOverrideRevisions[authIndex], auth.runtimeOverrideRevisions)
	m.runtimeAuthOverrideRevisions[authIndex] = revisions
	auth.runtimeOverrideRevisions = revisions
	return revisions
}

func prepareRuntimeAuthOverridePatch(
	clearRequested bool,
	clearFields []RuntimeAuthOverrideField,
	override RuntimeAuthOverride,
	ifRevisionField RuntimeAuthOverrideField,
	ifRevision *uint64,
	ifRevisions *RuntimeAuthOverrideRevisions,
) (runtimeAuthOverridePatch, error) {
	clearFields = append([]RuntimeAuthOverrideField(nil), clearFields...)
	if errValidate := validateRuntimeAuthOverrideFields(clearFields); errValidate != nil {
		return runtimeAuthOverridePatch{}, errValidate
	}
	normalized, errNormalize := normalizedRuntimeAuthOverridePatch(clearRequested, override)
	if errNormalize != nil {
		return runtimeAuthOverridePatch{}, errNormalize
	}
	touchedFields := runtimeAuthOverrideTouchedFields(clearRequested, clearFields, normalized)
	if ifRevisions != nil && (ifRevision != nil || ifRevisionField != "") {
		return runtimeAuthOverridePatch{}, &Error{
			Code:    "invalid_runtime_override",
			Message: "if_revisions is mutually exclusive with if_revision and if_revision_field",
		}
	}
	if errCondition := validateRuntimeAuthOverrideRevisionCondition(touchedFields, ifRevisionField, ifRevision); errCondition != nil {
		return runtimeAuthOverridePatch{}, errCondition
	}
	var expectedRevisions *RuntimeAuthOverrideRevisions
	if ifRevisions != nil {
		copied := *ifRevisions
		expectedRevisions = &copied
	}
	return runtimeAuthOverridePatch{
		clearRequested:  clearRequested,
		clearFields:     clearFields,
		override:        normalized,
		touchedFields:   touchedFields,
		ifRevisionField: ifRevisionField,
		ifRevision:      ifRevision,
		ifRevisions:     expectedRevisions,
	}, nil
}

func normalizedRuntimeAuthOverridePatch(clearRequested bool, override RuntimeAuthOverride) (RuntimeAuthOverride, error) {
	if !override.Empty() {
		return normalizeRuntimeAuthOverride(override)
	}
	if clearRequested {
		return RuntimeAuthOverride{}, nil
	}
	return RuntimeAuthOverride{}, &Error{
		Code:    "invalid_runtime_override",
		Message: "at least one runtime override field is required",
	}
}

func validateRuntimeAuthOverrideRevisionCondition(
	touchedFields []RuntimeAuthOverrideField,
	field RuntimeAuthOverrideField,
	revision *uint64,
) error {
	if revision == nil {
		return nil
	}
	if errValidate := validateRuntimeAuthOverrideFields([]RuntimeAuthOverrideField{field}); errValidate != nil {
		return errValidate
	}
	if containsRuntimeAuthOverrideField(touchedFields, field) {
		return nil
	}
	return &Error{
		Code:    "invalid_runtime_override",
		Message: "if_revision_field must be changed by the patch",
	}
}

func ensureRuntimeAuthOverrideRevisionsAvailable(
	revisions RuntimeAuthOverrideRevisions,
	fields []RuntimeAuthOverrideField,
) error {
	for _, field := range fields {
		if revisions.Revision(field) == math.MaxUint64 {
			return &Error{
				Code:    "runtime_override_revision_exhausted",
				Message: "runtime override revision is exhausted",
			}
		}
	}
	return nil
}

func runtimeAuthOverrideTouchedFields(
	clearRequested bool,
	clearFields []RuntimeAuthOverrideField,
	override RuntimeAuthOverride,
) []RuntimeAuthOverrideField {
	touched := make(map[RuntimeAuthOverrideField]struct{}, 3)
	if clearRequested && len(clearFields) == 0 {
		touched[RuntimeAuthOverrideDisabled] = struct{}{}
		touched[RuntimeAuthOverridePriority] = struct{}{}
		touched[RuntimeAuthOverrideProxyURL] = struct{}{}
	}
	for _, field := range clearFields {
		touched[field] = struct{}{}
	}
	if override.Disabled != nil {
		touched[RuntimeAuthOverrideDisabled] = struct{}{}
	}
	if override.Priority != nil {
		touched[RuntimeAuthOverridePriority] = struct{}{}
	}
	if override.ProxyURL != nil {
		touched[RuntimeAuthOverrideProxyURL] = struct{}{}
	}
	ordered := make([]RuntimeAuthOverrideField, 0, len(touched))
	for _, field := range []RuntimeAuthOverrideField{
		RuntimeAuthOverrideDisabled,
		RuntimeAuthOverridePriority,
		RuntimeAuthOverrideProxyURL,
	} {
		if _, ok := touched[field]; ok {
			ordered = append(ordered, field)
		}
	}
	return ordered
}

func containsRuntimeAuthOverrideField(fields []RuntimeAuthOverrideField, target RuntimeAuthOverrideField) bool {
	for _, field := range fields {
		if field == target {
			return true
		}
	}
	return false
}

func runtimeAuthOverrideRevisionsMatch(
	current RuntimeAuthOverrideRevisions,
	expected RuntimeAuthOverrideRevisions,
	fields []RuntimeAuthOverrideField,
) bool {
	for _, field := range fields {
		if current.Revision(field) != expected.Revision(field) {
			return false
		}
	}
	return true
}

func advanceRuntimeAuthOverrideRevision(revisions *RuntimeAuthOverrideRevisions, field RuntimeAuthOverrideField) {
	if revisions == nil {
		return
	}
	switch field {
	case RuntimeAuthOverrideDisabled:
		revisions.Disabled++
	case RuntimeAuthOverridePriority:
		revisions.Priority++
	case RuntimeAuthOverrideProxyURL:
		revisions.ProxyURL++
	}
}

func maxRuntimeAuthOverrideRevisions(left, right RuntimeAuthOverrideRevisions) RuntimeAuthOverrideRevisions {
	return RuntimeAuthOverrideRevisions{
		Disabled: max(left.Disabled, right.Disabled),
		Priority: max(left.Priority, right.Priority),
		ProxyURL: max(left.ProxyURL, right.ProxyURL),
	}
}
