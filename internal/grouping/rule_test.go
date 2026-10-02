package grouping

import "testing"

func TestRulesPermissionMatrix(t *testing.T) {
	rules, err := NewRules([]string{"group-a", "group-b"})
	if err != nil {
		t.Fatal(err)
	}
	groups := []string{AllGroups, "group-a", "group-b"}
	for _, tokenGroup := range groups {
		for _, credentialGroup := range groups {
			t.Run(tokenGroup+"/"+credentialGroup, func(t *testing.T) {
				token := activeBinding("token-id", Token, tokenGroup)
				credential := activeBinding("credential-id", Credential, credentialGroup)
				want := tokenGroup == AllGroups || credentialGroup == AllGroups || tokenGroup == credentialGroup
				if got := rules.Allows(token, credential); got != want {
					t.Fatalf("Allows = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestRulesRejectInvalidCatalog(t *testing.T) {
	cases := [][]string{
		{""}, {" "}, {" group-a"}, {"group-a "},
		{AllGroups}, {"group-a", "group-a"},
	}
	for _, groups := range cases {
		if rules, err := NewRules(groups); err == nil || rules != nil {
			t.Errorf("NewRules(%q) = (%v, %v), want nil rules and error", groups, rules, err)
		}
	}
}

func TestRulesEmptyCatalogAllowsOnlyExplicitAll(t *testing.T) {
	rules, err := NewRules(nil)
	if err != nil {
		t.Fatal(err)
	}
	token := activeBinding("token-id", Token, AllGroups)
	credential := activeBinding("credential-id", Credential, AllGroups)
	if !rules.Allows(token, credential) {
		t.Fatal("explicit all bindings should be allowed")
	}
	credential.GroupID = ""
	if rules.Allows(token, credential) {
		t.Fatal("missing binding group must not be treated as all")
	}
}

func TestRulesOwnsCatalog(t *testing.T) {
	groups := []string{"group-a"}
	rules, err := NewRules(groups)
	if err != nil {
		t.Fatal(err)
	}
	groups[0] = "group-b"
	token := activeBinding("token-id", Token, AllGroups)
	if !rules.Allows(token, activeBinding("credential-id", Credential, "group-a")) {
		t.Fatal("caller mutation changed the rule catalog")
	}
	if rules.Allows(token, activeBinding("credential-id", Credential, "group-b")) {
		t.Fatal("caller mutation admitted an unknown group")
	}
}

func activeBinding(id string, kind ObjectKind, group string) Binding {
	return Binding{ID: id, Kind: kind, GroupID: group, State: Active}
}
