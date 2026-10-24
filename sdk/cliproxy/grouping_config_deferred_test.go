package cliproxy

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestGroupingDeferredConfigReplaysWithoutAnotherWatcherHashChange(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	calls := 0
	w := newDeferredConfigWatcher(t, f, func(cfg *config.Config) {
		calls++
		f.service.applyWatcherConfigUpdate(cfg)
	})
	w.ReloadConfigIfChanged()
	if calls != 1 {
		t.Fatal("watcher did not prime the initial hash")
	}
	record := prepareDeferredOAuth(t, f)
	proposed := f.service.cfg.CloneForRuntime()
	proposed.Routing.Strategy = "fill-first"
	writeDeferredConfig(t, f, proposed)
	w.ReloadConfigIfChanged()
	if calls != 2 || f.service.cfg.Routing.Strategy == "fill-first" {
		t.Fatal("watcher reload bypassed OAuth isolation")
	}
	assertDeferredConfigState(t, f, true, true)
	w.ReloadConfigIfChanged()
	if calls != 2 {
		t.Fatal("identical watcher hash unexpectedly retried the pending reload")
	}
	saveDeferredOAuth(t, f, record)
	if err := f.service.grouping.finalizeOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	w.ReloadConfigIfChanged()
	if calls != 2 || f.service.cfg.Routing.Strategy != "fill-first" || f.service.appliedRoutingState.strategy != "fill-first" {
		t.Fatal("configuration did not reach runtime without a second watcher callback")
	}
	assertDeferredConfigState(t, f, false, true)
	if f.snapshot(t).Identities[record.Attributes["grouping_id"]].State != grouping.Active {
		t.Fatal("deferred reload lost the finalized OAuth source")
	}
}

func TestGroupingDeferredConfigLastCloneAndSynthesisModeWin(t *testing.T) {
	for _, synthesize := range []bool{false, true} {
		t.Run(map[bool]string{false: "watcher", true: "synchronous"}[synthesize], func(t *testing.T) {
			f := newGroupingInventoryFixture(t, false)
			f.activate(t)
			record := prepareDeferredOAuth(t, f)
			first := f.service.cfg.CloneForRuntime()
			first.Routing.Strategy = "fill-first"
			queueDeferredConfig(t, f, first, !synthesize)
			last := first.CloneForRuntime()
			last.Routing.Strategy = "weighted-round-robin"
			last.RequestRetry = 7
			queueDeferredConfig(t, f, last, synthesize)
			last.RequestRetry = 99
			last.OpenAICompatibility[0].APIKeyEntries[0].APIKey = "caller-mutation"
			published := 0
			f.service.updateServerClientsContextFn = func(_ context.Context, cfg *config.Config) bool {
				published++
				return cfg.Routing.Strategy == "weighted-round-robin" && cfg.RequestRetry == 7
			}
			saveDeferredOAuth(t, f, record)
			if err := f.service.grouping.finalizeOAuthRecord(f.ctx, record); err != nil {
				t.Fatal(err)
			}
			if published != 1 || f.service.cfg.RequestRetry != 7 || f.service.cfg.OpenAICompatibility[0].APIKeyEntries[0].APIKey == "caller-mutation" {
				t.Fatal("reload did not publish exactly the latest detached snapshot")
			}
			assertDeferredConfigState(t, f, false, true)
		})
	}
}

func TestGroupingDeferredConfigCanceledQueueDoesNotReplaceLatest(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	record := prepareDeferredOAuth(t, f)
	latest := f.service.cfg.CloneForRuntime()
	latest.RequestRetry = 7
	queueDeferredConfig(t, f, latest, true)
	canceled := latest.CloneForRuntime()
	canceled.RequestRetry = 99
	if f.service.applyConfigUpdateWithAuthSynthesis(canceledDeferredContext(), canceled, false) {
		t.Fatal("canceled reload succeeded")
	}
	saveDeferredOAuth(t, f, record)
	if err := f.service.grouping.finalizeOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if f.service.cfg.RequestRetry != 7 {
		t.Fatal("canceled caller replaced the last valid queued configuration")
	}
	assertDeferredConfigState(t, f, false, true)
}
