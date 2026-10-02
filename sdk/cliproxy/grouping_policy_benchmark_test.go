package cliproxy

import "testing"

var groupingCandidateResult bool

func BenchmarkGroupingCandidatePolicy(b *testing.B) {
	policy, credential, ctx := testGroupingPolicy(b)
	scope, err := policy.BeginAttempt(ctx)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("disabled_baseline", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			groupingCandidateResult = credential != nil && !credential.EffectiveDisabled()
		}
	})
	b.Run("enabled_candidate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			groupingCandidateResult = credential != nil && !credential.EffectiveDisabled() && scope.Allows(credential)
		}
	})
	b.Run("enabled_before_dispatch", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := scope.AuthorizeUse(ctx, credential); err != nil {
				b.Fatal(err)
			}
		}
	})
}
