package cliproxy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func (f *groupingIntegrationFixture) activate(t *testing.T) uint64 {
	t.Helper()
	result, err := f.backend.Apply(f.ctx, f.snapshot(t).Revision, groupingapi.Mutation{Operation: groupingapi.Activate, Enabled: true})
	if err != nil {
		t.Fatalf("real Service activation failed: %v", err)
	}
	if !f.service.grouping.enabled.Load() || !f.service.cfg.Grouping.Enabled || result.AppliedRevision != f.snapshot(t).Revision {
		t.Fatal("activation result does not match effective Service policy")
	}
	return result.AppliedRevision
}

func (f *groupingIntegrationFixture) credential(t *testing.T) *coreauth.Auth {
	t.Helper()
	auths, err := f.service.grouping.collectSources(f.service.cfg, nil)
	if err != nil || len(auths) == 0 {
		t.Fatalf("no synthesized credentials: %v", err)
	}
	return auths[0]
}

func TestGroupingIntegrationActivationAndConfirmedDisable(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	f.initialize(t)
	credential := f.credential(t)
	if err := f.service.coreManager.AuthorizeCredentialUse(context.Background(), credential); err != nil {
		t.Fatalf("initialization alone installed policy: %v", err)
	}
	revision := f.activate(t)
	if err := f.service.coreManager.AuthorizeCredentialUse(context.Background(), credential); err == nil {
		t.Fatal("enabled policy accepted a request without a trusted principal")
	}
	if err := f.service.coreManager.AuthorizeCredentialUse(f.principal(), credential); err != nil {
		t.Fatalf("all-group trusted token was denied: %v", err)
	}
	before := f.snapshot(t)
	configBefore, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.backend.Apply(f.ctx, revision, groupingapi.Mutation{Operation: groupingapi.Activate})
	if !errors.Is(err, groupingapi.ErrConflict) {
		t.Fatalf("disable without confirmation was not rejected: %v", err)
	}
	_, err = f.backend.Apply(f.ctx, revision-1, groupingapi.Mutation{Operation: groupingapi.Activate, ConfirmPermissionExpansion: true})
	if !errors.Is(err, groupingapi.ErrPrecondition) {
		t.Fatalf("stale activation was not rejected: %v", err)
	}
	configAfter, err := os.ReadFile(f.path)
	if err != nil || !bytes.Equal(configBefore, configAfter) || !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("rejected activation changed source configuration or policy")
	}
	result, err := f.backend.Apply(f.ctx, revision, groupingapi.Mutation{Operation: groupingapi.Activate, ConfirmPermissionExpansion: true})
	if err != nil || result.AppliedRevision != revision+1 || f.service.grouping.enabled.Load() || f.service.cfg.Grouping.Enabled {
		t.Fatalf("confirmed disable failed: %+v %v", result, err)
	}
	if err := f.service.coreManager.AuthorizeCredentialUse(context.Background(), credential); err != nil {
		t.Fatalf("confirmed disable did not remove grouping policy: %v", err)
	}
}

func TestGroupingIntegrationRestartRetainsIndependentBindings(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	f.initialize(t)
	groupA, groupB := f.createGroup(t, "Team A"), f.createGroup(t, "Team B")
	credential := f.credential(t)
	var tokenID string
	for _, identity := range f.snapshot(t).Identities {
		if identity.Kind == grouping.Token {
			tokenID = identity.ID
		}
	}
	f.bind(t, groupingapi.BindingRequest{TokenIDs: []string{tokenID}, GroupID: groupA})
	f.bind(t, groupingapi.BindingRequest{CredentialIDs: []string{credential.Attributes["grouping_id"]}, GroupID: groupB})
	f.activate(t)
	before := f.snapshot(t)
	if err := f.service.coreManager.AuthorizeCredentialUse(f.principal(), credential); err == nil {
		t.Fatal("cross-group request was allowed before restart")
	}
	if err := f.restart(t); err != nil {
		t.Fatalf("enabled restart failed: %v", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("restart reset identities or bindings")
	}
	if err := f.service.coreManager.AuthorizeCredentialUse(f.principal(), f.credential(t)); err == nil {
		t.Fatal("restart lost installed cross-group enforcement")
	}
}

func (f *groupingIntegrationFixture) createGroup(t *testing.T, name string) string {
	t.Helper()
	result, err := f.backend.Apply(f.ctx, f.snapshot(t).Revision, groupingapi.Mutation{Operation: groupingapi.CreateGroup, Name: name})
	if err != nil || result.Group == nil {
		t.Fatalf("create group failed: %v", err)
	}
	return result.Group.ID
}

func (f *groupingIntegrationFixture) bind(t *testing.T, request groupingapi.BindingRequest) {
	t.Helper()
	request.ConfirmPermissionExpansion = true
	if _, err := f.backend.Apply(f.ctx, f.snapshot(t).Revision, groupingapi.Mutation{Operation: groupingapi.Bind, Binding: request}); err != nil {
		t.Fatalf("binding failed: %v", err)
	}
}

func TestGroupingIntegrationDeletedAndPendingTokensAreDenied(t *testing.T) {
	for _, mode := range []string{"pending", "deleted"} {
		t.Run(mode, func(t *testing.T) {
			f := newGroupingIntegrationFixture(t)
			f.initialize(t)
			f.activate(t)
			credential := f.credential(t)
			if err := f.service.coreManager.AuthorizeCredentialUse(f.principal(), credential); err != nil {
				t.Fatalf("initial authorization failed: %v", err)
			}
			if mode == "pending" {
				markGroupingIntegrationTokenPending(t, f)
			} else {
				cfg := f.service.cfg.CloneForRuntime()
				cfg.APIKeys = []string{"integration-replacement-only"}
				if !f.service.applyConfigUpdateWithAuthSynthesis(f.ctx, cfg, true) {
					t.Fatal("real Service token-source reload failed")
				}
			}
			if err := f.service.coreManager.AuthorizeCredentialUse(f.principal(), credential); err == nil {
				t.Fatal("inactive or deleted token retained credential access")
			}
		})
	}
}

func markGroupingIntegrationTokenPending(t *testing.T, f *groupingIntegrationFixture) {
	t.Helper()
	g := f.service.grouping
	g.mu.Lock()
	defer g.mu.Unlock()
	_, err := g.store.Update(f.snapshot(t).Revision, func(snapshot *grouping.Snapshot) error {
		for id, identity := range snapshot.Identities {
			if identity.Kind == grouping.Token {
				return snapshot.SetIdentityState(id, grouping.PendingRebind)
			}
		}
		return grouping.ErrNotFound
	})
	if err != nil {
		t.Fatal(err)
	}
}
