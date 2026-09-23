package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type runtime429SettingsRequest struct {
	Auto429Enabled          *bool           `json:"auto_429_enabled"`
	Action                  *string         `json:"action"`
	TemporaryPriority       *int            `json:"temporary_priority"`
	Consecutive429Threshold json.RawMessage `json:"consecutive_429_threshold"`
}

type runtime429Settings struct {
	Auto429Enabled          bool
	Action                  string
	TemporaryPriority       int
	Consecutive429Threshold *int
}

type runtime429SettingsResult struct {
	configView
	Cleanup *restoreSummary `json:"cleanup,omitempty"`
}

func decodeRuntime429Settings(raw []byte) (runtime429Settings, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return runtime429Settings{}, fmt.Errorf("request body is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request runtime429SettingsRequest
	if errDecode := decoder.Decode(&request); errDecode != nil {
		return runtime429Settings{}, fmt.Errorf("invalid settings request: %w", errDecode)
	}
	if errTrailing := decoder.Decode(&struct{}{}); errTrailing != io.EOF {
		return runtime429Settings{}, fmt.Errorf("settings request must contain one JSON object")
	}
	if request.Auto429Enabled == nil {
		return runtime429Settings{}, fmt.Errorf("auto_429_enabled is required")
	}
	if request.Action == nil {
		return runtime429Settings{}, fmt.Errorf("action is required")
	}
	if request.TemporaryPriority == nil {
		return runtime429Settings{}, fmt.Errorf("temporary_priority is required")
	}
	consecutive429Threshold, errThreshold := decodeOptionalConsecutive429Threshold(request.Consecutive429Threshold)
	if errThreshold != nil {
		return runtime429Settings{}, errThreshold
	}
	action := *request.Action
	if action != strings.TrimSpace(action) || (action != actionDisable && action != actionPriority) {
		return runtime429Settings{}, fmt.Errorf("action must be %q or %q", actionDisable, actionPriority)
	}
	return runtime429Settings{
		Auto429Enabled:          *request.Auto429Enabled,
		Action:                  action,
		TemporaryPriority:       *request.TemporaryPriority,
		Consecutive429Threshold: consecutive429Threshold,
	}, nil
}

func decodeOptionalConsecutive429Threshold(raw json.RawMessage) (*int, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var value int
	if errDecode := json.Unmarshal(raw, &value); errDecode != nil {
		return nil, fmt.Errorf("consecutive_429_threshold must be an integer")
	}
	if value < 1 {
		return nil, fmt.Errorf("consecutive_429_threshold must be at least 1")
	}
	return &value, nil
}

func (a *application) applyRuntime429Settings(settings runtime429Settings) (guardConfig, restoreSummary) {
	a.guard.operations.Lock()
	defer a.guard.operations.Unlock()

	a.configMu.Lock()
	previousEnabled := a.config.Auto429Enabled
	a.config.Auto429Enabled = settings.Auto429Enabled
	a.config.Action = settings.Action
	a.config.TemporaryPriority = settings.TemporaryPriority
	if settings.Consecutive429Threshold != nil {
		a.config.Consecutive429Limit = *settings.Consecutive429Threshold
	}
	current := a.config
	a.configMu.Unlock()

	cleanup := restoreSummary{}
	if previousEnabled && !settings.Auto429Enabled {
		cleanup = a.guard.clearAutomaticOverridesLocked()
	} else if !previousEnabled && settings.Auto429Enabled {
		a.store.resetAllConsecutive429()
	}
	return current, cleanup
}
