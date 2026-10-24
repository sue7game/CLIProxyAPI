package grouping

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func accessFixture(t *testing.T) (Snapshot, Identity, Identity) {
	t.Helper()
	snapshot := NewSnapshot()
	group, err := snapshot.CreateGroup("Private")
	if err != nil {
		t.Fatal(err)
	}
	token := Identity{Binding: Binding{uuid.NewString(), Token, group.ID, Active}, Provider: "access", Fingerprint: "token-fingerprint"}
	credential := Identity{Binding: Binding{uuid.NewString(), Credential, group.ID, Active}, Provider: "upstream", Fingerprint: "credential-fingerprint"}
	for _, identity := range []Identity{token, credential} {
		if err := snapshot.Register(identity); err != nil {
			t.Fatal(err)
		}
	}
	return snapshot, token, credential
}

func TestAccessScopeIsolationAndUse(t *testing.T) {
	snapshot, token, credential := accessFixture(t)
	scope, err := BeginAccess(snapshot, token.Provider, token.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Allows(credential.ID, credential.Provider, credential.Fingerprint) {
		t.Fatal("same group denied")
	}
	if err := scope.AuthorizeUse(snapshot, credential.ID, credential.Provider, credential.Fingerprint); err != nil {
		t.Fatal(err)
	}
	delete(snapshot.Identities, credential.ID)
	if !scope.Allows(credential.ID, credential.Provider, credential.Fingerprint) {
		t.Fatal("scope aliases caller snapshot")
	}
	snapshot.Revision++
	if !errors.Is(scope.AuthorizeUse(snapshot, credential.ID, credential.Provider, credential.Fingerprint), ErrPolicyChanged) {
		t.Fatal("stale use was allowed")
	}
}

func TestAccessScopeRefusesMissingOrAmbiguousPrincipal(t *testing.T) {
	for _, scenario := range []string{"missing", "provider", "fingerprint", "pending", "tombstone", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			snapshot, token, _ := accessFixture(t)
			provider, fingerprint := token.Provider, token.Fingerprint
			switch scenario {
			case "missing":
				provider = ""
			case "provider":
				provider = "other"
			case "fingerprint":
				fingerprint = "other"
			case "pending":
				token.State = PendingRebind
				snapshot.Identities[token.ID] = token
			case "tombstone":
				token.State = Tombstone
				snapshot.Identities[token.ID] = token
			case "duplicate":
				token.ID = uuid.NewString()
				snapshot.Identities[token.ID] = token
			}
			if _, err := BeginAccess(snapshot, provider, fingerprint); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAccessScopeRejectsUnknownAndChangedCredentials(t *testing.T) {
	snapshot, token, credential := accessFixture(t)
	other, err := snapshot.CreateGroup("Other")
	if err != nil {
		t.Fatal(err)
	}
	foreign := credential
	foreign.ID, foreign.GroupID = uuid.NewString(), other.ID
	snapshot.Identities[foreign.ID] = foreign
	scope, err := BeginAccess(snapshot, token.Provider, token.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []Identity{foreign, {Binding: Binding{ID: "missing"}, Provider: credential.Provider, Fingerprint: credential.Fingerprint}} {
		if scope.Allows(identity.ID, identity.Provider, identity.Fingerprint) {
			t.Fatal("invalid credential allowed")
		}
	}
	if scope.Allows(credential.ID, credential.Provider, "rotated") {
		t.Fatal("unregistered replacement allowed")
	}
	if scope.Allows(credential.ID, "other", credential.Fingerprint) {
		t.Fatal("provider substitution allowed")
	}
	if err := scope.AuthorizeUse(snapshot, credential.ID, credential.Provider, "rotated"); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
	copy := snapshot.Clone()
	copy.Namespace = uuid.NewString()
	if err := scope.AuthorizeUse(copy, credential.ID, credential.Provider, credential.Fingerprint); !errors.Is(err, ErrPolicyChanged) {
		t.Fatalf("got %v", err)
	}
}

func TestAccessScopeWildcardNeverBypassesState(t *testing.T) {
	snapshot, token, credential := accessFixture(t)
	token.GroupID = AllGroups
	snapshot.Identities[token.ID] = token
	credential.State = PendingRebind
	snapshot.Identities[credential.ID] = credential
	scope, err := BeginAccess(snapshot, token.Provider, token.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if scope.Allows(credential.ID, credential.Provider, credential.Fingerprint) {
		t.Fatal("all bypassed quarantine")
	}
}
