package main

import (
	"testing"
	"time"
)

func TestCodexDisableRechecksCurrentConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		enabled, automatic, manual, wantApply bool
	}{
		{"plugin disabled automatic", false, true, false, false},
		{"plugin disabled unauthorized", false, true, true, false},
		{"automatic disabled", true, false, false, false},
		{"unauthorized independent of automatic", true, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Enabled, cfg.Auto429Enabled = tc.enabled, tc.automatic
			host := &fakeHost{auths: []hostAuthEntry{{AuthIndex: "codex-lifecycle", Provider: "codex"}}}
			g := newGuard(host, newStateStore(), func() guardConfig { return cfg })
			g.applyCodexDisable("codex-lifecycle", codexTriggerUsageLimit, time.Now().Add(time.Hour), "test", tc.manual)
			if got := len(host.overrides()) != 0; got != tc.wantApply {
				t.Fatalf("override applied = %t, want %t", got, tc.wantApply)
			}
		})
	}
}

func TestCodexCounterResetsAcrossAutomaticProtectionToggle(t *testing.T) {
	host := &fakeHost{}
	app := newApplication(host)
	t.Cleanup(app.shutdown)
	cfg := app.loadedConfig()
	for _, enabled := range []bool{false, true} {
		app.store.observeCodex("codex-counter", "usage_limit_reached", 429, nil, "", time.Now())
		app.applyRuntime429Settings(runtime429Settings{
			Auto429Enabled: enabled, Action: cfg.Action, TemporaryPriority: cfg.TemporaryPriority,
		})
		if got := app.store.snapshot("codex-counter", time.Now()).Codex.ConsecutiveUsageLimit; got != 0 {
			t.Fatalf("consecutive Codex failures after enabled=%t = %d, want 0", enabled, got)
		}
	}
}
