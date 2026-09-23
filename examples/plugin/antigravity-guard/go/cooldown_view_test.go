package main

import (
	"testing"
	"time"
)

func TestCooldownViewExposesPhaseRestoreTargetAndRetryTime(t *testing.T) {
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	temporaryPriority := 13
	originalPriority := 12
	nextAttempt := now.Add(2 * time.Minute)

	tests := []struct {
		name               string
		state              cooldownState
		configuredDisabled bool
		configuredPriority int
		wantPhase          string
		wantTarget         string
		wantNextAttempt    *time.Time
	}{
		{
			name: "cooling to original runtime priority",
			state: cooldownState{
				Active:           true,
				Action:           actionPriority,
				Priority:         &temporaryPriority,
				Until:            now.Add(time.Hour),
				OriginalPriority: &originalPriority,
			},
			configuredPriority: 14,
			wantPhase:          "cooling",
			wantTarget:         "runtime priority 12",
		},
		{
			name: "waiting to retry configured priority restore",
			state: cooldownState{
				Active:             true,
				Action:             actionPriority,
				Priority:           &temporaryPriority,
				Until:              now,
				LastError:          "temporary host failure",
				NextRestoreAttempt: nextAttempt,
			},
			configuredPriority: 14,
			wantPhase:          "retry_wait",
			wantTarget:         "configured priority 14",
			wantNextAttempt:    &nextAttempt,
		},
		{
			name: "restoring configured enabled state",
			state: cooldownState{
				Active:    true,
				Restoring: true,
				Action:    actionDisable,
				Until:     now,
			},
			configuredDisabled: false,
			configuredPriority: 14,
			wantPhase:          "restoring",
			wantTarget:         "configured enabled state",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := cooldownViewFromState(test.state, test.configuredDisabled, test.configuredPriority, now)
			if view == nil {
				t.Fatal("cooldown view is nil")
			}
			if view.Phase != test.wantPhase || view.RestoreTarget != test.wantTarget {
				t.Fatalf("cooldown view = %#v", view)
			}
			if test.wantNextAttempt == nil {
				if view.NextRestoreAttempt != nil {
					t.Fatalf("next restore attempt = %v, want nil", view.NextRestoreAttempt)
				}
				return
			}
			if view.NextRestoreAttempt == nil || !view.NextRestoreAttempt.Equal(*test.wantNextAttempt) {
				t.Fatalf("next restore attempt = %v, want %v", view.NextRestoreAttempt, *test.wantNextAttempt)
			}
		})
	}
}

func TestCooldownViewMarksWeeklyQuarantineForManualRelease(t *testing.T) {
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	priority := 13
	view := cooldownViewFromState(cooldownState{
		Active:                true,
		ManualReleaseRequired: true,
		Action:                actionDisable,
		Priority:              &priority,
		Trigger:               triggerWeeklyQuotaEmpty,
		Until:                 now.Add(5 * time.Hour),
	}, false, 14, now)

	if view == nil || !view.ManualReleaseRequired || view.Phase != "weekly_quarantine" || view.Priority == nil || *view.Priority != priority {
		t.Fatalf("weekly quarantine view = %#v", view)
	}
}

func TestDashboardExposesCompletedGuardOutcomes(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{
		testAntigravityAuth("ag-manual", 14),
		testAntigravityAuth("ag-restored", 14),
	}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }
	app.auth.now = func() time.Time { return now }

	app.guard.applyCooldown("ag-manual", actionPriority, 13, "quota_429", "Retry-After", now.Add(time.Hour))
	app.guard.applyCooldown("ag-restored", actionPriority, 13, "quota_429", "Retry-After", now.Add(time.Hour))
	manualPriority := 11
	host.setRuntimeOverride("ag-manual", &runtimeOverride{Priority: &manualPriority})
	now = now.Add(time.Hour)
	app.guard.restoreDue(now)

	dashboard, errDashboard := app.auth.dashboard()
	if errDashboard != nil {
		t.Fatal(errDashboard)
	}
	views := make(map[string]credentialView, len(dashboard.Credentials))
	for _, credential := range dashboard.Credentials {
		views[credential.AuthIndex] = credential
	}

	manual := views["ag-manual"]
	if manual.Cooldown != nil || manual.GuardOutcome == nil {
		t.Fatalf("manual takeover view = %#v", manual)
	}
	if manual.GuardOutcome.Outcome != restoreOutcomeManualTakeover || !manual.GuardOutcome.At.Equal(now) || manual.GuardOutcome.RestoreTarget != "configured priority 14" {
		t.Fatalf("manual takeover outcome = %#v", manual.GuardOutcome)
	}

	restored := views["ag-restored"]
	if restored.Cooldown != nil || restored.GuardOutcome == nil {
		t.Fatalf("restored view = %#v", restored)
	}
	if restored.GuardOutcome.Outcome != restoreOutcomeRestored || !restored.GuardOutcome.At.Equal(now) || restored.GuardOutcome.RestoreTarget != "configured priority 14" {
		t.Fatalf("restored outcome = %#v", restored.GuardOutcome)
	}
}

func TestCompletedGuardOutcomeKeepsRestoreTimeConfiguredTarget(t *testing.T) {
	host := &fakeHost{auths: []hostAuthEntry{testAntigravityAuth("ag-target-snapshot", 14)}}
	app := newApplication(host)
	defer app.shutdown()
	now := time.Date(2030, time.July, 25, 12, 0, 0, 0, time.UTC)
	app.guard.now = func() time.Time { return now }
	app.auth.now = func() time.Time { return now }

	app.guard.applyCooldown("ag-target-snapshot", actionPriority, 13, "quota_429", "Retry-After", now.Add(time.Hour))
	host.setConfiguredPriority("ag-target-snapshot", 15)
	now = now.Add(time.Hour)
	app.guard.restoreDue(now)
	host.setConfiguredPriority("ag-target-snapshot", 16)

	dashboard, errDashboard := app.auth.dashboard()
	if errDashboard != nil {
		t.Fatal(errDashboard)
	}
	if len(dashboard.Credentials) != 1 || dashboard.Credentials[0].GuardOutcome == nil {
		t.Fatalf("dashboard credentials = %#v", dashboard.Credentials)
	}
	outcome := dashboard.Credentials[0].GuardOutcome
	if outcome.RestoreTarget != "configured priority 15" {
		t.Fatalf("completed restore target = %q, want restore-time snapshot", outcome.RestoreTarget)
	}
}
