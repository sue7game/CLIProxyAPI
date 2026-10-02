package grouping

import (
	"sync"
	"testing"
)

func TestRulesRejectInvalidIdentityEvenWithWildcard(t *testing.T) {
	rules, err := NewRules([]string{"group-a"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Binding)
	}{
		{"missing-id", func(b *Binding) { b.ID = "" }},
		{"blank-id", func(b *Binding) { b.ID = " " }},
		{"padded-id", func(b *Binding) { b.ID = " id " }},
		{"missing-kind", func(b *Binding) { b.Kind = "" }},
		{"unknown-kind", func(b *Binding) { b.Kind = "admin" }},
		{"missing-group", func(b *Binding) { b.GroupID = "" }},
		{"unknown-group", func(b *Binding) { b.GroupID = "missing" }},
		{"padded-group", func(b *Binding) { b.GroupID = " all " }},
		{"missing-state", func(b *Binding) { b.State = "" }},
		{"unknown-state", func(b *Binding) { b.State = "unknown" }},
		{"pending", func(b *Binding) { b.State = PendingRebind }},
		{"tombstone", func(b *Binding) { b.State = Tombstone }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := activeBinding("token-id", Token, AllGroups)
			credential := activeBinding("credential-id", Credential, AllGroups)
			invalidToken, invalidCredential := token, credential
			tc.mutate(&invalidToken)
			tc.mutate(&invalidCredential)
			if rules.Allows(invalidToken, credential) || rules.Allows(token, invalidCredential) {
				t.Fatal("wildcard bypassed invalid identity")
			}
		})
	}
}

func TestRulesRejectSwappedKindsAndZeroValue(t *testing.T) {
	rules, err := NewRules(nil)
	if err != nil {
		t.Fatal(err)
	}
	token := activeBinding("token-id", Token, AllGroups)
	credential := activeBinding("credential-id", Credential, AllGroups)
	if rules.Allows(credential, token) || rules.Allows(token, token) || rules.Allows(credential, credential) {
		t.Fatal("incorrect object roles were accepted")
	}
	for _, unavailable := range []*Rules{nil, {}} {
		if unavailable.Allows(token, credential) {
			t.Fatal("uninitialized rules must fail closed")
		}
	}
}

func TestRulesConcurrentReads(t *testing.T) {
	rules, err := NewRules([]string{"group-a", "group-b"})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			token := activeBinding("token-id", Token, "group-a")
			for range 100 {
				if !rules.Allows(token, activeBinding("allowed", Credential, "group-a")) {
					t.Error("same-group credential denied")
				}
				if rules.Allows(token, activeBinding("denied", Credential, "group-b")) {
					t.Error("cross-group credential allowed")
				}
			}
		})
	}
	workers.Wait()
}
