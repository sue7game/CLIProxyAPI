package cliproxy

import (
	"context"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestGroupingDeferredConfigBlocksSelectionUntilRuntimeRetirement(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	auth := groupingInventoryCredential(t, f)
	record := prepareDeferredOAuth(t, f)
	proposed := f.service.cfg.CloneForRuntime()
	proposed.OpenAICompatibility[0].Disabled = true
	queueDeferredConfig(t, f, proposed, true)
	saveDeferredOAuth(t, f, record)
	finish := blockDeferredFinalization(t, f, f.ctx, record)
	assertDeferredConfigState(t, f, true, false)
	assertGroupingInventoryScheduling(t, f, auth, true)
	if len(GlobalModelRegistry().GetModelsForClient(auth.ID)) == 0 {
		t.Fatal("test did not block before obsolete models were retired")
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	assertDeferredConfigState(t, f, false, true)
	assertInventoryRuntimeRetired(t, f, auth.ID)
	assertGroupingInventoryScheduling(t, f, auth, true)
	if f.snapshot(t).Identities[auth.Attributes["grouping_id"]].State != grouping.Active {
		t.Fatal("runtime retirement removed the disabled source's persistent identity")
	}
}

func TestGroupingDeferredConfigCancellationDuringRuntimeRemainsClosed(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	auth := groupingInventoryCredential(t, f)
	record := prepareDeferredOAuth(t, f)
	queueDeferredConfig(t, f, f.service.cfg.CloneForRuntime(), true)
	saveDeferredOAuth(t, f, record)
	ctx, cancel := context.WithCancel(f.ctx)
	t.Cleanup(cancel)
	finish := blockDeferredFinalization(t, f, ctx, record)
	assertGroupingInventoryScheduling(t, f, auth, true)
	cancel()
	if err := finish(); !errors.Is(err, context.Canceled) {
		t.Fatalf("runtime cancellation did not return a replay failure: %v", err)
	}
	assertDeferredConfigState(t, f, true, false)
	assertGroupingInventoryScheduling(t, f, auth, true)
}
