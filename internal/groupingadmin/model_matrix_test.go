package groupingadmin

import (
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestRegisteredModelPreviewMatchesAuthorizationMatrix(t *testing.T) {
	base := grouping.NewSnapshot()
	groups := []string{grouping.AllGroups}
	for _, name := range []string{"A", "B", "C"} {
		group, err := base.CreateGroup(name)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, group.ID)
	}
	rules, err := grouping.NewRules(groups[1:])
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	catalog := map[string][]string{ids[2]: {"shared", "m1", "shared"}, ids[3]: {"m2", "shared"}}
	for layout := range 256 {
		snapshot := previewLayout(base, groups, ids, layout)
		for _, target := range groups {
			for mask := range 16 {
				changed := previewSelection(snapshot, ids, target, mask)
				before, after, err := indexCatalogModels(snapshot, catalog, target, changed)
				if err != nil {
					t.Fatal(err)
				}
				got := modelAccessChanges(snapshot, target, changed, before, after)
				want := bruteModelChanges(snapshot, rules, catalog, target, changed)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("layout=%d target=%s mask=%d got=%+v want=%+v", layout, target, mask, got, want)
				}
			}
		}
	}
}

func bruteModelChanges(before grouping.Snapshot, rules *grouping.Rules, catalog map[string][]string, target string, changed map[string]struct{}) []groupingapi.ModelAccessChange {
	after := before.Clone()
	for id := range changed {
		identity := after.Identities[id]
		identity.GroupID = target
		after.Identities[id] = identity
	}
	result := make([]groupingapi.ModelAccessChange, 0)
	for id, token := range before.Identities {
		if token.Kind != grouping.Token || token.State != grouping.Active {
			continue
		}
		previous := bruteTokenModels(before, rules, catalog, id)
		next := bruteTokenModels(after, rules, catalog, id)
		change := groupingapi.ModelAccessChange{TokenID: id,
			Before: sortedModelKeys(previous), After: sortedModelKeys(next), Added: []string{}, Removed: []string{}}
		for model := range previous {
			if !next[model] {
				change.Removed = append(change.Removed, model)
			}
		}
		for model := range next {
			if !previous[model] {
				change.Added = append(change.Added, model)
			}
		}
		sort.Strings(change.Added)
		sort.Strings(change.Removed)
		if len(change.Added) != 0 || len(change.Removed) != 0 {
			result = append(result, change)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TokenID < result[j].TokenID })
	return result
}

func bruteTokenModels(snapshot grouping.Snapshot, rules *grouping.Rules, catalog map[string][]string, tokenID string) map[string]bool {
	models := make(map[string]bool)
	for id, credential := range snapshot.Identities {
		if rules.Allows(snapshot.Identities[tokenID].Binding, credential.Binding) {
			for _, model := range catalog[id] {
				models[model] = true
			}
		}
	}
	return models
}

func sortedModelKeys(set map[string]bool) []string {
	models := make([]string, 0, len(set))
	for model := range set {
		models = append(models, model)
	}
	sort.Strings(models)
	return models
}
