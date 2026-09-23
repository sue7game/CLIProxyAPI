package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var errNotAntigravity = errors.New("credential is not an Antigravity credential")

type authIndexRequest struct {
	AuthIndex string `json:"auth_index"`
}

type proxyActionRequest struct {
	AuthIndex       string   `json:"auth_index,omitempty"`
	AuthIndices     []string `json:"auth_indices,omitempty"`
	Mode            string   `json:"mode"`
	ProxyURL        string   `json:"proxy_url,omitempty"`
	SourceAuthIndex string   `json:"source_auth_index,omitempty"`
}

type proxyActionResult struct {
	Updated []string          `json:"updated"`
	Failed  map[string]string `json:"failed,omitempty"`
}

func (a *application) handleManagement(raw []byte) ([]byte, error) {
	var request managementRequest
	if errDecode := json.Unmarshal(raw, &request); errDecode != nil {
		return nil, fmt.Errorf("decode management request: %w", errDecode)
	}
	if strings.HasPrefix(request.Path, resourceBasePath+"/") {
		response, errResource := resourceResponse(request.Path)
		if errResource != nil {
			return nil, errResource
		}
		return okEnvelope(response)
	}
	response := a.dispatchManagement(request)
	return okEnvelope(response)
}

func (a *application) dispatchManagement(request managementRequest) managementResponse {
	switch request.Method + " " + request.Path {
	case http.MethodGet + " " + managementAPIPath + "/state":
		return a.stateResponse()
	case http.MethodPost + " " + managementAPIPath + "/quota":
		return a.quotaResponse(request.Body, request.HostCallbackID)
	case http.MethodPost + " " + managementAPIPath + "/proxy":
		return a.proxyResponse(request.Body)
	case http.MethodPost + " " + managementAPIPath + "/proxy/alias":
		return a.proxyAliasResponse(request.Body)
	case http.MethodPost + " " + managementAPIPath + "/settings":
		return a.settingsResponse(request.Body)
	case http.MethodPost + " " + managementAPIPath + "/cooldown/clear":
		return a.clearCooldownResponse(request.Body)
	case http.MethodPost + " " + managementAPIPath + "/recover":
		return a.manualRecoverResponse(request.Body)
	default:
		return jsonError(http.StatusNotFound, "management route not found")
	}
}

func (a *application) settingsResponse(raw []byte) managementResponse {
	settings, errDecode := decodeRuntime429Settings(raw)
	if errDecode != nil {
		return jsonError(http.StatusBadRequest, errDecode.Error())
	}
	config, cleanup := a.applyRuntime429Settings(settings)
	result := runtime429SettingsResult{configView: configurationView(config)}
	if cleanup.Attempted > 0 {
		result.Cleanup = &cleanup
	}
	return jsonResponse(http.StatusOK, result)
}

func (a *application) stateResponse() managementResponse {
	state, errState := a.auth.dashboard()
	if errState != nil {
		return jsonError(http.StatusBadGateway, errState.Error())
	}
	return jsonResponse(http.StatusOK, state)
}

func (a *application) quotaResponse(raw []byte, hostCallbackID string) managementResponse {
	var request authIndexRequest
	if errDecode := json.Unmarshal(raw, &request); errDecode != nil {
		return jsonError(http.StatusBadRequest, "invalid quota request")
	}
	entry, response := a.authorizeTarget(request.AuthIndex)
	if response.StatusCode != 0 {
		return response
	}
	result, errRefresh := a.quota.refresh(entry.AuthIndex, entry.ProjectID, hostCallbackID)
	if errRefresh != nil {
		return jsonError(http.StatusBadGateway, errRefresh.Error())
	}
	state := a.store.snapshot(entry.AuthIndex, a.auth.now())
	return jsonResponse(http.StatusOK, map[string]any{
		"auth_index":   entry.AuthIndex,
		"weekly_quota": weeklyViewFromState(state.Quota, a.auth.now()),
		"found":        result.Found,
	})
}

func (a *application) proxyResponse(raw []byte) managementResponse {
	var request proxyActionRequest
	if errDecode := json.Unmarshal(raw, &request); errDecode != nil {
		return jsonError(http.StatusBadRequest, "invalid proxy request")
	}
	authIndices, errIndices := normalizedAuthIndices(request)
	if errIndices != nil {
		return jsonError(http.StatusBadRequest, errIndices.Error())
	}
	proxyURL, clear, response := a.resolveProxyAction(request)
	if response.StatusCode != 0 {
		return response
	}
	for index, authIndex := range authIndices {
		entry, response := a.authorizeTarget(authIndex)
		if response.StatusCode != 0 {
			return response
		}
		authIndices[index] = entry.AuthIndex
	}
	result := proxyActionResult{Failed: make(map[string]string)}
	for _, authIndex := range authIndices {
		var value *string
		if !clear {
			value = &proxyURL
		}
		if errSet := a.guard.setProxy(authIndex, value); errSet != nil {
			result.Failed[authIndex] = errSet.Error()
			continue
		}
		result.Updated = append(result.Updated, authIndex)
	}
	if len(result.Failed) == 0 {
		result.Failed = nil
		return jsonResponse(http.StatusOK, result)
	}
	return jsonResponse(http.StatusMultiStatus, result)
}

func (a *application) resolveProxyAction(request proxyActionRequest) (string, bool, managementResponse) {
	if !strings.EqualFold(strings.TrimSpace(request.Mode), "copy") {
		proxyURL, clear, errAction := proxyAction(request)
		if errAction != nil {
			return "", false, jsonError(http.StatusBadRequest, errAction.Error())
		}
		return proxyURL, clear, managementResponse{}
	}

	source, response := a.authorizeTarget(request.SourceAuthIndex)
	if response.StatusCode != 0 {
		return "", false, response
	}
	proxyURL, _ := effectiveProxy(source, source.ConfiguredProxyURL)
	if proxyURL == "" || strings.EqualFold(proxyURL, "direct") {
		return "", false, jsonError(http.StatusBadRequest, "source credential does not use a reusable proxy; use mode=direct when needed")
	}
	validated, errValidate := validateProxyURL(proxyURL)
	if errValidate != nil {
		return "", false, jsonError(http.StatusBadRequest, errValidate.Error())
	}
	return validated, false, managementResponse{}
}

func (a *application) clearCooldownResponse(raw []byte) managementResponse {
	var request authIndexRequest
	if errDecode := json.Unmarshal(raw, &request); errDecode != nil {
		return jsonError(http.StatusBadRequest, "invalid cooldown request")
	}
	entry, response := a.authorizeTarget(request.AuthIndex)
	if response.StatusCode != 0 {
		return response
	}
	if errClear := a.guard.clearCooldown(entry.AuthIndex); errClear != nil {
		return jsonError(http.StatusBadGateway, errClear.Error())
	}
	return jsonResponse(http.StatusOK, map[string]any{"auth_index": entry.AuthIndex, "cleared": true})
}

func (a *application) manualRecoverResponse(raw []byte) managementResponse {
	var request authIndexRequest
	if errDecode := json.Unmarshal(raw, &request); errDecode != nil {
		return jsonError(http.StatusBadRequest, "invalid recovery request")
	}
	entry, response := a.authorizeRecoveryTarget(request.AuthIndex)
	if response.StatusCode != 0 {
		return response
	}
	if errRecover := a.guard.manualRecover(entry.AuthIndex); errRecover != nil {
		return jsonError(http.StatusBadGateway, errRecover.Error())
	}
	return jsonResponse(http.StatusOK, map[string]any{"auth_index": entry.AuthIndex, "recovered": true})
}

func (a *application) authorizeTarget(rawAuthIndex string) (hostAuthEntry, managementResponse) {
	authIndex, errValidate := validateAuthIndex(rawAuthIndex)
	if errValidate != nil {
		return hostAuthEntry{}, jsonError(http.StatusBadRequest, errValidate.Error())
	}
	entries, errList := a.host.ListAuths()
	if errList != nil {
		return hostAuthEntry{}, jsonError(http.StatusBadGateway, errList.Error())
	}
	for _, entry := range entries {
		if entry.AuthIndex != authIndex {
			continue
		}
		if !isAntigravityEntry(entry) {
			return hostAuthEntry{}, jsonError(http.StatusForbidden, errNotAntigravity.Error())
		}
		return entry, managementResponse{}
	}
	return hostAuthEntry{}, jsonError(http.StatusNotFound, "credential not found")
}

func (a *application) authorizeRecoveryTarget(rawAuthIndex string) (hostAuthEntry, managementResponse) {
	authIndex, errValidate := validateAuthIndex(rawAuthIndex)
	if errValidate != nil {
		return hostAuthEntry{}, jsonError(http.StatusBadRequest, errValidate.Error())
	}
	entries, errList := a.host.ListAuths()
	if errList != nil {
		return hostAuthEntry{}, jsonError(http.StatusBadGateway, errList.Error())
	}
	for _, entry := range entries {
		if entry.AuthIndex != authIndex {
			continue
		}
		if !isAntigravityEntry(entry) && !isCodexEntry(entry) {
			return hostAuthEntry{}, jsonError(http.StatusForbidden, "credential type does not support manual recovery")
		}
		return entry, managementResponse{}
	}
	return hostAuthEntry{}, jsonError(http.StatusNotFound, "credential not found")
}

func normalizedAuthIndices(request proxyActionRequest) ([]string, error) {
	values := append([]string(nil), request.AuthIndices...)
	if strings.TrimSpace(request.AuthIndex) != "" {
		values = append(values, request.AuthIndex)
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("auth_index or auth_indices is required")
	}
	return result, nil
}

func proxyAction(request proxyActionRequest) (string, bool, error) {
	switch strings.ToLower(strings.TrimSpace(request.Mode)) {
	case "clear":
		return "", true, nil
	case "direct":
		return "direct", false, nil
	case "set":
		proxyURL, errValidate := validateProxyURL(request.ProxyURL)
		if errValidate != nil {
			return "", false, errValidate
		}
		if proxyURL == "" || proxyURL == "direct" {
			return "", false, fmt.Errorf("mode=set requires a proxy URL; use mode=direct for forced direct")
		}
		return proxyURL, false, nil
	default:
		return "", false, fmt.Errorf("mode must be set, copy, direct, or clear")
	}
}

func jsonResponse(status int, value any) managementResponse {
	body, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		return jsonError(http.StatusInternalServerError, errMarshal.Error())
	}
	return managementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type":  []string{"application/json; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: body,
	}
}

func jsonError(status int, message string) managementResponse {
	return jsonResponseValue(status, map[string]string{"error": message})
}

func jsonResponseValue(status int, value any) managementResponse {
	body, _ := json.Marshal(value)
	return managementResponse{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}, "Cache-Control": []string{"no-store"}},
		Body:       body,
	}
}
