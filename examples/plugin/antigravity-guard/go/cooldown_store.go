package main

import (
	"sort"
	"time"
)

type cooldownSpec struct {
	Action                string
	Priority              *int
	Trigger               string
	Until                 time.Time
	RetrySource           string
	ApplyDisabled         bool
	ApplyPriority         bool
	ManualReleaseRequired bool
}

type restoreTask struct {
	AuthIndex               string
	Generation              uint64
	OriginalDisabled        *bool
	OriginalPriority        *int
	AppliedDisabled         *bool
	AppliedPriority         *int
	AppliedDisabledRevision uint64
	AppliedPriorityRevision uint64
	DisabledRestored        bool
	PriorityRestored        bool
	RestoreManualTakeover   bool
}

func (s *stateStore) beginCooldown(
	authIndex, action string,
	priority int,
	trigger, retrySource string,
	until time.Time,
) (uint64, bool) {
	spec := cooldownSpec{
		Action:      action,
		Trigger:     trigger,
		Until:       until,
		RetrySource: retrySource,
	}
	if action == actionPriority {
		spec.Priority = &priority
		spec.ApplyPriority = true
	} else {
		spec.ApplyDisabled = true
	}
	return s.beginGuardState(authIndex, spec)
}

func (s *stateStore) beginWeeklyQuarantine(
	authIndex string,
	priority int,
	until time.Time,
	retrySource string,
) (uint64, bool) {
	return s.beginGuardState(authIndex, cooldownSpec{
		Action:                actionDisable,
		Priority:              &priority,
		Trigger:               triggerWeeklyQuotaEmpty,
		Until:                 until,
		RetrySource:           retrySource,
		ApplyDisabled:         true,
		ApplyPriority:         true,
		ManualReleaseRequired: true,
	})
}

func (s *stateStore) beginManualDisable(authIndex, trigger, retrySource string, until time.Time) (uint64, bool) {
	return s.beginGuardState(authIndex, cooldownSpec{
		Action: actionDisable, Trigger: trigger, RetrySource: retrySource, Until: until,
		ApplyDisabled: true, ManualReleaseRequired: true,
	})
}

func (s *stateStore) beginGuardState(authIndex string, spec cooldownSpec) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	cooldown := &state.Cooldown
	if cooldown.Active || cooldown.Pending {
		if spec.ApplyDisabled && cooldown.AppliedDisabled == nil {
			disabled := true
			cooldown.AppliedDisabled = &disabled
			cooldown.Action = spec.Action
			cooldown.Trigger = spec.Trigger
			cooldown.RetrySource = spec.RetrySource
			cooldown.ManualReleaseRequired = cooldown.ManualReleaseRequired || spec.ManualReleaseRequired
			if spec.Until.After(cooldown.Until) {
				cooldown.Until = spec.Until
			}
			return cooldown.Generation, true
		}
		updateActiveCooldown(cooldown, spec)
		return cooldown.Generation, false
	}

	generation := cooldown.Generation + 1
	*cooldown = cooldownState{
		Pending:               true,
		ManualReleaseRequired: spec.ManualReleaseRequired,
		Generation:            generation,
		Action:                spec.Action,
		Priority:              cloneInt(spec.Priority),
		Trigger:               spec.Trigger,
		Until:                 spec.Until,
		RetrySource:           spec.RetrySource,
	}
	if spec.ApplyDisabled {
		disabled := true
		cooldown.AppliedDisabled = &disabled
	}
	if spec.ApplyPriority {
		cooldown.AppliedPriority = cloneInt(spec.Priority)
	}
	return generation, true
}

func updateActiveCooldown(cooldown *cooldownState, spec cooldownSpec) {
	if cooldown.ManualReleaseRequired && !spec.ManualReleaseRequired {
		return
	}
	if spec.Until.After(cooldown.Until) {
		cooldown.Until = spec.Until
	}
	cooldown.Trigger = spec.Trigger
	cooldown.RetrySource = spec.RetrySource
	if spec.ManualReleaseRequired {
		cooldown.ManualReleaseRequired = true
	}
	cooldown.LastError = ""
}

func (s *stateStore) setCooldownOriginal(authIndex string, generation uint64, original *runtimeOverride) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	if state.Cooldown.Generation != generation || !state.Cooldown.Pending {
		return
	}
	if original == nil {
		return
	}
	state.Cooldown.OriginalDisabled = cloneBool(original.Disabled)
	state.Cooldown.OriginalPriority = cloneInt(original.Priority)
}

func (s *stateStore) completeCooldownStart(
	authIndex string,
	generation uint64,
	revisions runtimeOverrideRevisions,
	err error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	if state.Cooldown.Generation != generation {
		return
	}
	state.Cooldown.Pending = false
	if err != nil {
		state.Cooldown.Active = false
		state.Cooldown.LastError = err.Error()
		return
	}
	state.Cooldown.Active = true
	state.Cooldown.LastError = ""
	if state.Cooldown.AppliedDisabled != nil {
		state.Cooldown.AppliedDisabledRevision = revisions.Disabled
	}
	if state.Cooldown.AppliedPriority != nil {
		state.Cooldown.AppliedPriorityRevision = revisions.Priority
	}
}

func (s *stateStore) claimDue(now time.Time) []restoreTask {
	s.mu.Lock()
	defer s.mu.Unlock()
	tasks := make([]restoreTask, 0)
	for authIndex, state := range s.credentials {
		cooldown := &state.Cooldown
		if !cooldownReadyToRestore(cooldown, now) {
			continue
		}
		cooldown.Restoring = true
		tasks = append(tasks, restoreTaskFromState(authIndex, *cooldown))
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].AuthIndex < tasks[j].AuthIndex })
	return tasks
}

func cooldownReadyToRestore(cooldown *cooldownState, now time.Time) bool {
	if !cooldown.Active || cooldown.Restoring || now.Before(cooldown.Until) {
		return false
	}
	if cooldown.ManualReleaseRequired && !cooldown.RestoreRequested {
		return false
	}
	return cooldown.NextRestoreAttempt.IsZero() || !now.Before(cooldown.NextRestoreAttempt)
}

func (s *stateStore) claimImmediate(authIndex string, now time.Time) (restoreTask, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	cooldown := &state.Cooldown
	if !cooldown.Active || cooldown.Pending || cooldown.Restoring {
		return restoreTask{}, false
	}
	cooldown.Until = now
	cooldown.NextRestoreAttempt = time.Time{}
	cooldown.RestoreRequested = true
	cooldown.Restoring = true
	return restoreTaskFromState(authIndex, *cooldown), true
}

func (s *stateStore) completeRestore(
	task restoreTask,
	outcome, restoreTarget string,
	err error,
	now, nextAttempt time.Time,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(task.AuthIndex)
	if state.Cooldown.Generation != task.Generation {
		return
	}
	copyRestoreProgress(&state.Cooldown, task)
	state.Cooldown.Restoring = false
	if err != nil {
		state.Cooldown.LastError = err.Error()
		state.Cooldown.NextRestoreAttempt = nextAttempt
		return
	}
	completeRestoredCooldown(state, outcome, restoreTarget, now)
}

func copyRestoreProgress(cooldown *cooldownState, task restoreTask) {
	cooldown.DisabledRestored = task.DisabledRestored
	cooldown.PriorityRestored = task.PriorityRestored
	cooldown.RestoreManualTakeover = task.RestoreManualTakeover
}

func completeRestoredCooldown(state *credentialState, outcome, restoreTarget string, now time.Time) {
	completed := state.Cooldown
	completed.Active = false
	completed.Pending = false
	completed.Restoring = false
	completed.LastError = ""
	completed.NextRestoreAttempt = time.Time{}
	completed.RestoreOutcome = outcome
	completed.RestoredAt = now
	completed.Superseded = outcome == restoreOutcomeManualTakeover
	completed.RestoreTargetSnapshot = restoreTarget
	state.Cooldown = completed
	state.Usage.Consecutive429 = 0
	state.Codex.ConsecutiveUsageLimit = 0
}

func (s *stateStore) clearCooldown(authIndex string) cooldownState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	previous := state.Cooldown
	state.Cooldown = cooldownState{Generation: previous.Generation + 1}
	state.Usage.Consecutive429 = 0
	state.Codex.ConsecutiveUsageLimit = 0
	return previous
}

func (s *stateStore) abandonCooldown(authIndex string, outcome, restoreTarget string, now time.Time) cooldownState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.getLocked(authIndex)
	previous := state.Cooldown
	state.Cooldown = cooldownState{
		Generation:            previous.Generation + 1,
		RestoreOutcome:        outcome,
		RestoreTargetSnapshot: restoreTarget,
		RestoredAt:            now,
		Superseded:            outcome == restoreOutcomeManualTakeover,
	}
	state.Usage.Consecutive429 = 0
	state.Codex.ConsecutiveUsageLimit = 0
	return previous
}
