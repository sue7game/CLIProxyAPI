package cliproxy

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func BenchmarkGroupingPolicyScale(b *testing.B) {
	for _, count := range []int{10, 1000, 10000} {
		b.Run(fmt.Sprintf("identities_%d", count), func(b *testing.B) {
			policy, credential, ctx := testGroupingPolicy(b)
			addBenchmarkIdentities(b, policy.store, count-2)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				scope, err := policy.BeginAttempt(ctx)
				if err != nil {
					b.Fatal(err)
				}
				if !scope.Allows(credential) {
					b.Fatal("registered credential denied")
				}
				if err := scope.AuthorizeUse(ctx, credential); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func addBenchmarkIdentities(b *testing.B, store *grouping.Store, count int) {
	b.Helper()
	snapshot, err := store.Snapshot()
	if err != nil {
		b.Fatal(err)
	}
	_, err = store.Update(snapshot.Revision, func(snapshot *grouping.Snapshot) error {
		for i := range count {
			id := uuid.NewString()
			snapshot.Identities[id] = grouping.Identity{
				Binding:  grouping.Binding{ID: id, Kind: grouping.Credential, GroupID: grouping.AllGroups, State: grouping.Active},
				Provider: "codex", Fingerprint: fmt.Sprintf("benchmark-credential-%d", i),
			}
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
}
