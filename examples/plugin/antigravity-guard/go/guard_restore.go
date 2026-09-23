package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type restoreSummary struct {
	Attempted      int               `json:"attempted"`
	Restored       int               `json:"restored"`
	ManualTakeover int               `json:"manual_takeover"`
	Failed         map[string]string `json:"failed,omitempty"`
}

func (s *restoreSummary) add(authIndex, outcome string, err error) {
	s.Attempted++
	if err != nil {
		if s.Failed == nil {
			s.Failed = make(map[string]string)
		}
		s.Failed[authIndex] = err.Error()
		return
	}
	if outcome == restoreOutcomeManualTakeover {
		s.ManualTakeover++
		return
	}
	s.Restored++
}

func (g *guard) authEntry(authIndex string) (hostAuthEntry, error) {
	entries, errList := g.host.ListAuths()
	if errList != nil {
		return hostAuthEntry{}, fmt.Errorf("list credentials: %w", errList)
	}
	for _, entry := range entries {
		if entry.AuthIndex == authIndex {
			return entry, nil
		}
	}
	return hostAuthEntry{}, fmt.Errorf("credential %q was not found", authIndex)
}

func (g *guard) restoreDue(now time.Time) {
	g.operations.Lock()
	defer g.operations.Unlock()
	for _, task := range g.store.claimDue(now) {
		_, _ = g.finishRestore(task, now)
	}
}

func (g *guard) reconcileConfiguredDisables(now time.Time) {
	snapshots := g.store.allSnapshots(now)
	needsReconcile := false
	for _, state := range snapshots {
		if state.Cooldown.Active {
			needsReconcile = true
			break
		}
	}
	if !needsReconcile {
		return
	}
	entries, errList := g.host.ListAuths()
	if errList != nil {
		return
	}
	g.operations.Lock()
	defer g.operations.Unlock()
	for _, entry := range entries {
		if !entry.ConfiguredDisabled {
			continue
		}
		state := snapshots[entry.AuthIndex]
		if !configuredDisableClearsCooldown(entry, state.Cooldown) {
			continue
		}
		if entry.RuntimeOverride == nil || entry.RuntimeOverride.Disabled == nil || !*entry.RuntimeOverride.Disabled {
			target := restoreTargetForResponse(restoreTaskFromState(entry.AuthIndex, state.Cooldown), entry)
			g.store.abandonCooldown(entry.AuthIndex, restoreOutcomeManualTakeover, target, now)
			if isCodexEntry(entry) {
				g.store.clearCodexErrorState(entry.AuthIndex)
			}
			continue
		}
		task, claimed := g.store.claimImmediate(entry.AuthIndex, now)
		if !claimed {
			continue
		}
		_, errRestore := g.finishRestore(task, now)
		if errRestore == nil && isCodexEntry(entry) {
			g.store.clearCodexErrorState(entry.AuthIndex)
		}
	}
}

func configuredDisableClearsCooldown(entry hostAuthEntry, cooldown cooldownState) bool {
	if !cooldown.Active {
		return false
	}
	if isCodexEntry(entry) {
		return true
	}
	return cooldown.Trigger == triggerWeeklyQuotaEmpty
}

func (g *guard) finishRestore(task restoreTask, now time.Time) (string, error) {
	updatedTask, outcome, restoreTarget, errRestore := g.restoreTask(task)
	nextAttempt := now.Add(g.config().RestoreRetry)
	g.store.completeRestore(updatedTask, outcome, restoreTarget, errRestore, now, nextAttempt)
	return outcome, errRestore
}

func (g *guard) restoreTask(task restoreTask) (restoreTask, string, string, error) {
	var entry hostAuthEntry
	if task.AppliedPriority != nil && !task.PriorityRestored {
		responseEntry, applied, errRestore := g.restoreField(task, "priority")
		if errRestore != nil {
			return task, "", "", errRestore
		}
		entry = responseEntry
		task.PriorityRestored = true
		if !applied {
			task.RestoreManualTakeover = true
		}
	}
	if task.AppliedDisabled != nil && !task.DisabledRestored {
		responseEntry, applied, errRestore := g.restoreField(task, "disabled")
		if errRestore != nil {
			return task, "", "", errRestore
		}
		entry = responseEntry
		task.DisabledRestored = true
		if !applied {
			task.RestoreManualTakeover = true
		}
	}
	if entry.AuthIndex == "" {
		return task, "", "", fmt.Errorf("cooldown has no runtime fields to restore")
	}
	outcome := restoreOutcomeRestored
	if task.RestoreManualTakeover {
		outcome = restoreOutcomeManualTakeover
	}
	return task, outcome, restoreTargetForResponse(task, entry), nil
}

func (g *guard) restoreField(task restoreTask, field string) (hostAuthEntry, bool, error) {
	request, revision, errRequest := restoreOverrideRequest(task, field)
	if errRequest != nil {
		return hostAuthEntry{}, false, errRequest
	}
	request.IfRevision = &revision
	request.IfRevisionField = field
	response, errSet := g.host.SetRuntimeOverride(request)
	if errSet != nil {
		return hostAuthEntry{}, false, errSet
	}
	return response.Auth, response.Applied, nil
}

func restoreTargetForResponse(task restoreTask, entry hostAuthEntry) string {
	configuredPriority := entry.ConfiguredPriority
	if configuredPriority == 0 {
		configuredPriority = entry.Priority
	}
	configuredDisabled := entry.ConfiguredDisabled || entry.Disabled
	targets := make([]string, 0, 2)
	if task.AppliedPriority != nil {
		targets = append(targets, restoreTargetForField(task, "priority", configuredDisabled, configuredPriority))
	}
	if task.AppliedDisabled != nil {
		targets = append(targets, restoreTargetForField(task, "disabled", configuredDisabled, configuredPriority))
	}
	return strings.Join(targets, "; ")
}

func restoreTargetForField(task restoreTask, field string, configuredDisabled bool, configuredPriority int) string {
	state := cooldownState{
		Action:           actionDisable,
		OriginalDisabled: cloneBool(task.OriginalDisabled),
		OriginalPriority: cloneInt(task.OriginalPriority),
	}
	if field == "priority" {
		state.Action = actionPriority
	}
	return state.restoreTarget(configuredDisabled, configuredPriority)
}

func restoreOverrideRequest(task restoreTask, field string) (runtimeOverrideRequest, uint64, error) {
	request := runtimeOverrideRequest{AuthIndex: task.AuthIndex}
	switch field {
	case "disabled":
		if task.OriginalDisabled == nil {
			request.Clear = []string{"disabled"}
		} else {
			request.Disabled = cloneBool(task.OriginalDisabled)
		}
		return request, task.AppliedDisabledRevision, nil
	case "priority":
		if task.OriginalPriority == nil {
			request.Clear = []string{"priority"}
		} else {
			request.Priority = cloneInt(task.OriginalPriority)
		}
		return request, task.AppliedPriorityRevision, nil
	default:
		return runtimeOverrideRequest{}, 0, fmt.Errorf("unknown cooldown field %q", field)
	}
}

func (g *guard) clearCooldown(authIndex string) error {
	g.operations.Lock()
	defer g.operations.Unlock()
	return g.clearCooldownLocked(authIndex)
}

func (g *guard) clearCooldownLocked(authIndex string) error {
	state := g.store.snapshot(authIndex, g.now())
	if !state.Cooldown.Active {
		g.store.clearCooldown(authIndex)
		return nil
	}
	task, claimed := g.store.claimImmediate(authIndex, g.now())
	if !claimed {
		return fmt.Errorf("cooldown restore is already in progress")
	}
	_, errRestore := g.finishRestore(task, g.now())
	return errRestore
}

// manualRecover clears plugin-owned status and routing overrides for one credential.
// The configured disabled flag remains owned by CPA and is never changed here.
func (g *guard) manualRecover(authIndex string) error {
	g.operations.Lock()
	defer g.operations.Unlock()

	if errClear := g.clearCooldownLocked(authIndex); errClear != nil {
		return errClear
	}
	entry, errEntry := g.authEntry(authIndex)
	if errEntry != nil {
		return errEntry
	}
	if isCodexEntry(entry) && entry.RuntimeOverride != nil && entry.RuntimeOverride.Disabled != nil && *entry.RuntimeOverride.Disabled {
		response, errSet := g.host.SetRuntimeOverride(runtimeOverrideRequest{
			AuthIndex:       authIndex,
			Clear:           []string{"disabled"},
			IfRevisionField: "disabled",
			IfRevision:      ptr(entry.RuntimeOverrideRevisions.Disabled),
		})
		if errSet != nil {
			return errSet
		}
		if !response.Applied {
			return fmt.Errorf("runtime override changed while manually recovering credential")
		}
	}
	g.store.clearGuardState(authIndex)
	return nil
}

func (g *guard) clearAutomaticOverrides() restoreSummary {
	g.operations.Lock()
	defer g.operations.Unlock()
	return g.clearAutomaticOverridesLocked()
}

func (g *guard) clearAutomaticOverridesLocked() restoreSummary {
	g.store.resetAllConsecutive429()
	now := g.now()
	snapshots := g.store.allSnapshots(now)
	authIndices := make([]string, 0, len(snapshots))
	for authIndex, state := range snapshots {
		if state.Cooldown.Active {
			authIndices = append(authIndices, authIndex)
		}
	}
	sort.Strings(authIndices)
	summary := restoreSummary{}
	for _, authIndex := range authIndices {
		task, claimed := g.store.claimImmediate(authIndex, now)
		if !claimed {
			continue
		}
		outcome, errRestore := g.finishRestore(task, now)
		summary.add(authIndex, outcome, errRestore)
	}
	return summary
}
