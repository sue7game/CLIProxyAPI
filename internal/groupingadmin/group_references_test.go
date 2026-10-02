package groupingadmin

import (
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func TestGroupDeletionRetainsInactiveIdentityReferences(t *testing.T) {
	for _, kind := range []grouping.ObjectKind{grouping.Token, grouping.Credential} {
		for _, state := range []grouping.RegistrationState{grouping.PendingRebind, grouping.Tombstone} {
			t.Run(string(kind)+"/"+string(state), func(t *testing.T) {
				f := newFixture(t, sourceRecord{"inactive", kind, "A", state})
				before, data := snapshotOf(t, f), policyBytes(t, f)
				result, err := f.backend.Apply(testContext(), before.Revision, groupingapi.Mutation{
					Operation: groupingapi.DeleteGroup, ID: f.groups["A"],
				})
				if !errors.Is(err, groupingapi.ErrConflict) || result.AppliedRevision != 0 {
					t.Fatalf("inactive reference did not prevent group deletion: %+v %v", result, err)
				}
				assertUnchanged(t, f, before, data)
			})
		}
	}
}
