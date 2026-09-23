package main

import (
	"sync"
)

type fakeHost struct {
	mu               sync.Mutex
	auths            []hostAuthEntry
	overrideRequests []runtimeOverrideRequest
	authRequests     []hostAuthRequest
	listError        error
	overrideError    error
	overrideErrors   []error
	requestResponse  hostAuthResponse
	requestError     error
}

func (h *fakeHost) ListAuths() ([]hostAuthEntry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.listError != nil {
		return nil, h.listError
	}
	return cloneHostAuthEntries(h.auths), nil
}

func (h *fakeHost) SetRuntimeOverride(request runtimeOverrideRequest) (runtimeOverrideResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.overrideRequests = append(h.overrideRequests, request)
	if len(h.overrideErrors) > 0 {
		errOverride := h.overrideErrors[0]
		h.overrideErrors = h.overrideErrors[1:]
		if errOverride != nil {
			return runtimeOverrideResponse{}, errOverride
		}
	}
	if h.overrideError != nil {
		return runtimeOverrideResponse{}, h.overrideError
	}
	for index := range h.auths {
		if h.auths[index].AuthIndex != request.AuthIndex {
			continue
		}
		if request.IfRevisions != nil && !fakeRuntimeOverrideRevisionsMatch(
			h.auths[index].RuntimeOverrideRevisions,
			*request.IfRevisions,
			fakeRuntimeOverrideTouchedFields(request),
		) {
			entry := cloneHostAuthEntry(h.auths[index])
			return fakeRuntimeOverrideResponse(entry, false, ""), nil
		}
		if request.IfRevision != nil && h.auths[index].RuntimeOverrideRevisions.forField(request.IfRevisionField) != *request.IfRevision {
			entry := cloneHostAuthEntry(h.auths[index])
			return fakeRuntimeOverrideResponse(entry, false, request.IfRevisionField), nil
		}
		touchedFields := fakeRuntimeOverrideTouchedFields(request)
		applyFakeRuntimeOverride(&h.auths[index], request)
		for _, field := range touchedFields {
			advanceFakeRuntimeOverrideRevision(&h.auths[index].RuntimeOverrideRevisions, field)
		}
		entry := cloneHostAuthEntry(h.auths[index])
		return fakeRuntimeOverrideResponse(entry, true, fakeResponseRevisionField(request)), nil
	}
	return runtimeOverrideResponse{}, nil
}

func fakeRuntimeOverrideRevisionsMatch(
	current runtimeOverrideRevisions,
	expected runtimeOverrideRevisions,
	fields []string,
) bool {
	for _, field := range fields {
		if current.forField(field) != expected.forField(field) {
			return false
		}
	}
	return true
}

func (h *fakeHost) Request(request hostAuthRequest) (hostAuthResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authRequests = append(h.authRequests, request)
	return h.requestResponse, h.requestError
}

func (h *fakeHost) overrides() []runtimeOverrideRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]runtimeOverrideRequest(nil), h.overrideRequests...)
}

func (h *fakeHost) setRuntimeOverride(authIndex string, override *runtimeOverride) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for index := range h.auths {
		if h.auths[index].AuthIndex != authIndex {
			continue
		}
		current := h.auths[index].RuntimeOverride
		h.auths[index].RuntimeOverride = cloneRuntimeOverride(override)
		for _, field := range manuallyTouchedRuntimeOverrideFields(current, override) {
			advanceFakeRuntimeOverrideRevision(&h.auths[index].RuntimeOverrideRevisions, field)
		}
		return
	}
}

func fakeRuntimeOverrideResponse(entry hostAuthEntry, applied bool, revisionField string) runtimeOverrideResponse {
	response := runtimeOverrideResponse{
		Applied:   applied,
		Revision:  entry.RuntimeOverrideRevisions.forField(revisionField),
		Revisions: entry.RuntimeOverrideRevisions,
		Auth:      entry,
	}
	if entry.RuntimeOverride != nil {
		response.RuntimeOverride = *entry.RuntimeOverride
	}
	return response
}

func fakeRuntimeOverrideTouchedFields(request runtimeOverrideRequest) []string {
	touched := make(map[string]struct{}, 3)
	for _, field := range request.Clear {
		touched[field] = struct{}{}
	}
	if request.Disabled != nil {
		touched["disabled"] = struct{}{}
	}
	if request.Priority != nil {
		touched["priority"] = struct{}{}
	}
	if request.ProxyURL != nil {
		touched["proxy_url"] = struct{}{}
	}
	return orderedRuntimeOverrideFields(touched)
}

func fakeResponseRevisionField(request runtimeOverrideRequest) string {
	if request.IfRevisionField != "" {
		return request.IfRevisionField
	}
	fields := fakeRuntimeOverrideTouchedFields(request)
	if len(fields) == 1 {
		return fields[0]
	}
	return ""
}

func manuallyTouchedRuntimeOverrideFields(current, next *runtimeOverride) []string {
	touched := make(map[string]struct{}, 3)
	if current != nil {
		if current.Disabled != nil {
			touched["disabled"] = struct{}{}
		}
		if current.Priority != nil {
			touched["priority"] = struct{}{}
		}
		if current.ProxyURL != nil {
			touched["proxy_url"] = struct{}{}
		}
	}
	if next != nil {
		if next.Disabled != nil {
			touched["disabled"] = struct{}{}
		}
		if next.Priority != nil {
			touched["priority"] = struct{}{}
		}
		if next.ProxyURL != nil {
			touched["proxy_url"] = struct{}{}
		}
	}
	return orderedRuntimeOverrideFields(touched)
}

func orderedRuntimeOverrideFields(fields map[string]struct{}) []string {
	ordered := make([]string, 0, len(fields))
	for _, field := range []string{"disabled", "priority", "proxy_url"} {
		if _, ok := fields[field]; ok {
			ordered = append(ordered, field)
		}
	}
	return ordered
}

func advanceFakeRuntimeOverrideRevision(revisions *runtimeOverrideRevisions, field string) {
	switch field {
	case "disabled":
		revisions.Disabled++
	case "priority":
		revisions.Priority++
	case "proxy_url":
		revisions.ProxyURL++
	}
}

func (h *fakeHost) setConfiguredPriority(authIndex string, priority int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for index := range h.auths {
		if h.auths[index].AuthIndex == authIndex {
			h.auths[index].ConfiguredPriority = priority
			h.auths[index].Priority = priority
		}
	}
}

func (h *fakeHost) setConfiguredDisabled(authIndex string, disabled bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for index := range h.auths {
		if h.auths[index].AuthIndex != authIndex {
			continue
		}
		h.auths[index].ConfiguredDisabled = disabled
		h.auths[index].Disabled = disabled
	}
}

func (h *fakeHost) setOverrideError(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.overrideError = err
}

func applyFakeRuntimeOverride(entry *hostAuthEntry, request runtimeOverrideRequest) {
	current := runtimeOverride{}
	if entry.RuntimeOverride != nil {
		current = *cloneRuntimeOverride(entry.RuntimeOverride)
	}
	for _, field := range request.Clear {
		switch field {
		case "disabled":
			current.Disabled = nil
		case "priority":
			current.Priority = nil
		case "proxy_url":
			current.ProxyURL = nil
		}
	}
	if request.Disabled != nil {
		current.Disabled = cloneBool(request.Disabled)
	}
	if request.Priority != nil {
		current.Priority = cloneInt(request.Priority)
	}
	if request.ProxyURL != nil {
		value := *request.ProxyURL
		current.ProxyURL = &value
	}
	if current.Disabled == nil && current.Priority == nil && current.ProxyURL == nil {
		entry.RuntimeOverride = nil
		return
	}
	entry.RuntimeOverride = cloneRuntimeOverride(&current)
}

func cloneHostAuthEntries(entries []hostAuthEntry) []hostAuthEntry {
	cloned := make([]hostAuthEntry, len(entries))
	for index := range entries {
		cloned[index] = cloneHostAuthEntry(entries[index])
	}
	return cloned
}

func cloneHostAuthEntry(entry hostAuthEntry) hostAuthEntry {
	entry.RuntimeOverride = cloneRuntimeOverride(entry.RuntimeOverride)
	return entry
}

func cloneRuntimeOverride(override *runtimeOverride) *runtimeOverride {
	if override == nil {
		return nil
	}
	cloned := &runtimeOverride{
		Disabled: cloneBool(override.Disabled),
		Priority: cloneInt(override.Priority),
	}
	if override.ProxyURL != nil {
		value := *override.ProxyURL
		cloned.ProxyURL = &value
	}
	return cloned
}

func testConfig() guardConfig {
	config, errConfig := normalizeConfig(defaultPluginConfig())
	if errConfig != nil {
		panic(errConfig)
	}
	return config
}

func testAntigravityAuth(authIndex string, priority int) hostAuthEntry {
	return hostAuthEntry{
		AuthIndex:          authIndex,
		Name:               authIndex + ".json",
		Provider:           "antigravity",
		Priority:           priority,
		ConfiguredPriority: priority,
		EffectivePriority:  priority,
	}
}
