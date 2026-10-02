package cliproxy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func testGroupingPolicy(t testing.TB) (*groupingAccessPolicy, *coreauth.Auth, context.Context) {
	t.Helper()
	store, err := grouping.InitializeStore(filepath.Join(t.TempDir(), "policy"), grouping.NewSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	credential := &coreauth.Auth{ID: "runtime", Provider: "codex", Attributes: map[string]string{"source": "config:codex[test]", "api_key": "test-upstream-only", "grouping_id": uuid.NewString()}}
	hash, err := store.IdentityHasher()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := groupingCredentialIdentity(credential, hash)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := hash("token:"+sdkaccess.DefaultAccessProviderName, "test-downstream-only")
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Update(1, func(snapshot *grouping.Snapshot) error {
		if err := snapshot.Register(identity); err != nil {
			return err
		}
		return snapshot.Register(grouping.Identity{Binding: grouping.Binding{ID: uuid.NewString(), Kind: grouping.Token, GroupID: grouping.AllGroups, State: grouping.Active}, Provider: sdkaccess.DefaultAccessProviderName, Fingerprint: fingerprint})
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := &groupingAccessPolicy{store: store, principalCurrent: func(p sdkaccess.AuthenticatedPrincipal) bool {
		return p.Provider == sdkaccess.DefaultAccessProviderName && p.Subject == "test-downstream-only"
	}}
	ctx := sdkaccess.WithAuthenticatedPrincipal(context.Background(), sdkaccess.DefaultAccessProviderName, "test-downstream-only")
	return policy, credential, ctx
}

func TestGroupingPolicyRequiresTrustedCurrentPrincipal(t *testing.T) {
	policy, credential, ctx := testGroupingPolicy(t)
	if _, err := policy.BeginAttempt(context.Background()); !errors.Is(err, grouping.ErrUnauthenticated) {
		t.Fatalf("anonymous: %v", err)
	}
	scope, err := policy.BeginAttempt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Allows(credential) {
		t.Fatal("registered credential denied")
	}
	if err := scope.AuthorizeUse(ctx, credential); err != nil {
		t.Fatal(err)
	}
	policy.principalCurrent = func(sdkaccess.AuthenticatedPrincipal) bool { return false }
	if err := scope.AuthorizeUse(ctx, credential); !errors.Is(err, grouping.ErrUnauthenticated) {
		t.Fatalf("revoked issuer: %v", err)
	}
}

func TestGroupingPolicyRejectsVersionAndSourceChanges(t *testing.T) {
	policy, credential, ctx := testGroupingPolicy(t)
	scope, err := policy.BeginAttempt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replacement := credential.Clone()
	replacement.Attributes["api_key"] = "test-replacement-only"
	if scope.Allows(replacement) {
		t.Fatal("unregistered replacement accepted")
	}
	_, err = policy.store.Update(2, func(snapshot *grouping.Snapshot) error { _, err := snapshot.CreateGroup("new"); return err })
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.AuthorizeUse(ctx, credential); err == nil {
		t.Fatal("stale scope authorized")
	}
	fresh, err := policy.BeginAttempt(ctx)
	if err != nil || !fresh.Allows(credential) {
		t.Fatalf("fresh scope: %v", err)
	}
}

func TestGroupingCredentialIdentityIgnoresRoutingAndOAuthRefresh(t *testing.T) {
	policy, credential, _ := testGroupingPolicy(t)
	hash, err := policy.store.IdentityHasher()
	if err != nil {
		t.Fatal(err)
	}
	before, err := groupingCredentialIdentity(credential, hash)
	if err != nil {
		t.Fatal(err)
	}
	credential.ProxyURL, credential.Prefix = "http://localhost:9090", "prefix"
	credential.Attributes["header:User-Agent"] = "different"
	after, err := groupingCredentialIdentity(credential, hash)
	if err != nil || before != after {
		t.Fatalf("routing changed identity: %v", err)
	}
	credential.Attributes = map[string]string{"grouping_id": uuid.NewString(), "source": "account.json"}
	credential.Metadata = map[string]any{"account_id": "test-account", "access_token": "old-test-token"}
	before, err = groupingCredentialIdentity(credential, hash)
	if err != nil {
		t.Fatal(err)
	}
	credential.Metadata["access_token"] = "new-test-token"
	after, err = groupingCredentialIdentity(credential, hash)
	if err != nil || before != after {
		t.Fatalf("refresh changed identity: %v", err)
	}
}

func TestGroupingHomeConfigRefusedBeforeCommitAndStartup(t *testing.T) {
	current := &config.Config{}
	service := &Service{cfg: current}
	incompatible := current.CloneForRuntime()
	incompatible.Grouping.Enabled, incompatible.Home.Enabled = true, true
	if commit := service.commitConfigUpdate(incompatible); commit.cfg != nil {
		t.Fatal("incompatible config committed")
	}
	if service.cfg != current {
		t.Fatal("failed commit replaced active configuration")
	}
	if err := (&Service{cfg: incompatible}).Run(context.Background()); err == nil {
		t.Fatal("incompatible mode started")
	}
}
