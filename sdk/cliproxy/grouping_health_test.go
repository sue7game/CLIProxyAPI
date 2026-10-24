package cliproxy

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
)

func TestGroupingUnsafeReloadDeniesUntilValidSourceIsRestored(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	f.initialize(t)
	f.activate(t)
	auth := f.credential(t)
	valid := f.service.cfg.CloneForRuntime()
	invalid := valid.CloneForRuntime()
	invalid.CodexKey[0].GroupingID = ""
	if f.service.applyConfigUpdateWithAuthSynthesis(f.ctx, invalid, true) {
		t.Fatal("missing source ID was accepted")
	}
	if err := f.service.coreManager.AuthorizeCredentialUse(f.principal(), auth); err == nil {
		t.Fatal("unsafe source reload left proxy authorization ready")
	}
	status, err := f.backend.Status(f.ctx)
	if err != nil || status.Healthy {
		t.Fatal("source failure was not visible to management")
	}
	if _, err := f.backend.Apply(f.ctx, f.snapshot(t).Revision, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: "unsafe-write"}); err == nil {
		t.Fatal("unhealthy runtime accepted policy mutation")
	}
	if !f.service.applyConfigUpdateWithAuthSynthesis(f.ctx, valid, true) {
		t.Fatal("valid restored configuration was refused")
	}
	if err := f.service.coreManager.AuthorizeCredentialUse(f.principal(), auth); err != nil {
		t.Fatalf("restored source did not become ready: %v", err)
	}
}
