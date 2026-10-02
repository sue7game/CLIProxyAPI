package cliproxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestGroupingDeferredConfigCanceledFinalizeRetainsQueueAndCloses(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	auth := groupingInventoryCredential(t, f)
	record := prepareDeferredOAuth(t, f)
	proposed := f.service.cfg.CloneForRuntime()
	proposed.RequestRetry = 7
	queueDeferredConfig(t, f, proposed, true)
	saveDeferredOAuth(t, f, record)
	err := f.service.grouping.finalizeOAuthRecord(canceledDeferredContext(), record)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "deferred configuration") {
		t.Fatalf("canceled replay did not return its failure: %v", err)
	}
	if f.service.grouping.sourcePending {
		t.Fatal("persisted OAuth source was not finalized before replay cancellation")
	}
	assertDeferredConfigState(t, f, true, false)
	assertGroupingInventoryScheduling(t, f, auth, true)
	if !f.service.applyConfigUpdateWithAuthSynthesis(f.ctx, proposed, true) {
		t.Fatal("explicit valid retry did not recover canceled replay")
	}
	assertDeferredConfigState(t, f, false, true)
	assertGroupingInventoryScheduling(t, f, auth, false)
}

func TestGroupingDeferredConfigRuntimeFailureRetainsQueueUntilNewerSuccess(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	auth := groupingInventoryCredential(t, f)
	record := prepareDeferredOAuth(t, f)
	proposed := f.service.cfg.CloneForRuntime()
	proposed.RequestRetry = 7
	queueDeferredConfig(t, f, proposed, true)
	saveDeferredOAuth(t, f, record)
	f.service.updateServerClientsContextFn = func(context.Context, *config.Config) bool { return false }
	if err := f.service.grouping.finalizeOAuthRecord(f.ctx, record); err == nil || !strings.Contains(err.Error(), "deferred configuration replay failed") {
		t.Fatalf("runtime rejection returned success: %v", err)
	}
	assertDeferredConfigState(t, f, true, false)
	assertGroupingInventoryScheduling(t, f, auth, true)
	f.service.updateServerClientsContextFn = nil
	newer := proposed.CloneForRuntime()
	newer.RequestRetry = 11
	if !f.service.applyConfigUpdateWithAuthSynthesis(f.ctx, newer, true) {
		t.Fatal("new valid configuration could not supersede failed replay")
	}
	if err := f.service.grouping.finalizeOAuthRecord(f.ctx, record); err != nil {
		t.Fatal(err)
	}
	if f.service.cfg.RequestRetry != 11 {
		t.Fatal("stale deferred configuration replaced a newer successful configuration")
	}
	assertDeferredConfigState(t, f, false, true)
	assertGroupingInventoryScheduling(t, f, auth, false)
}

func TestGroupingDeferredConfigOAuthFailureRetainsQueueAndRestartUsesDisk(t *testing.T) {
	f := newGroupingInventoryFixture(t, false)
	f.activate(t)
	auth := groupingInventoryCredential(t, f)
	record := prepareDeferredOAuth(t, f)
	proposed := f.service.cfg.CloneForRuntime()
	proposed.RequestRetry = 7
	writeDeferredConfig(t, f, proposed)
	queueDeferredConfig(t, f, proposed, false)
	if err := f.service.grouping.finalizeOAuthRecord(f.ctx, record); err == nil {
		t.Fatal("missing persisted OAuth source returned success")
	}
	assertDeferredConfigState(t, f, true, false)
	assertGroupingInventoryScheduling(t, f, auth, true)
	if err := f.restart(t); err != nil {
		t.Fatal("signed before-state could not recover", err)
	}
	if !f.service.applyConfigUpdateWithAuthSynthesis(f.ctx, f.service.cfg, true) {
		t.Fatal("restarted service could not publish configuration from disk")
	}
	if f.service.cfg.RequestRetry != 7 {
		t.Fatal("restart discarded the latest on-disk configuration")
	}
	if _, exists := f.snapshot(t).Identities[record.Attributes["grouping_id"]]; exists {
		t.Fatal("recovery trusted an OAuth source that was never saved")
	}
	if _, err := os.Stat(filepath.Join(f.service.grouping.path, "config.pending")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery left the source journal behind")
	}
	assertDeferredConfigState(t, f, false, true)
	assertGroupingInventoryScheduling(t, f, auth, false)
}
