package main

import (
	"fmt"
	"time"
)

func restoreTaskFromState(authIndex string, state cooldownState) restoreTask {
	return restoreTask{
		AuthIndex:               authIndex,
		Generation:              state.Generation,
		OriginalDisabled:        cloneBool(state.OriginalDisabled),
		OriginalPriority:        cloneInt(state.OriginalPriority),
		AppliedDisabled:         cloneBool(state.AppliedDisabled),
		AppliedPriority:         cloneInt(state.AppliedPriority),
		AppliedDisabledRevision: state.AppliedDisabledRevision,
		AppliedPriorityRevision: state.AppliedPriorityRevision,
		DisabledRestored:        state.DisabledRestored,
		PriorityRestored:        state.PriorityRestored,
		RestoreManualTakeover:   state.RestoreManualTakeover,
	}
}

func (state cooldownState) phase(now time.Time) string {
	switch {
	case state.Pending:
		return "applying"
	case state.Restoring:
		return "restoring"
	case state.Active && state.LastError != "" && !state.NextRestoreAttempt.IsZero():
		return "retry_wait"
	case state.Active && state.ManualReleaseRequired && state.Trigger == triggerWeeklyQuotaEmpty:
		return "weekly_quarantine"
	case state.Active && state.ManualReleaseRequired:
		return "manual_release"
	case state.Active:
		return "cooling"
	case state.Superseded:
		return restoreOutcomeManualTakeover
	case state.RestoreOutcome == restoreOutcomeRestored:
		return restoreOutcomeRestored
	case state.LastError != "":
		return "apply_failed"
	default:
		return "idle"
	}
}

func (state cooldownState) restoreTarget(configuredDisabled bool, configuredPriority int) string {
	if state.Action == actionPriority {
		if state.OriginalPriority != nil {
			return fmt.Sprintf("runtime priority %d", *state.OriginalPriority)
		}
		return fmt.Sprintf("configured priority %d", configuredPriority)
	}
	if state.OriginalDisabled != nil {
		if *state.OriginalDisabled {
			return "runtime disabled"
		}
		return "runtime enabled"
	}
	if configuredDisabled {
		return "configured disabled state"
	}
	return "configured enabled state"
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
