package groupingadmin

import (
	"sort"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

type credentialCounts struct {
	byGroup map[string]int
	total   int
}

func (counts credentialCounts) accessible(group string) int {
	if group == grouping.AllGroups {
		return counts.total
	}
	return counts.byGroup[grouping.AllGroups] + counts.byGroup[group]
}

func (counts credentialCounts) intersection(before, after string) int {
	if before == grouping.AllGroups {
		return counts.accessible(after)
	}
	if after == grouping.AllGroups || before == after {
		return counts.accessible(before)
	}
	return counts.byGroup[grouping.AllGroups]
}

func countCredentials(snapshot grouping.Snapshot, changed map[string]struct{}) (credentialCounts, credentialCounts) {
	stable := credentialCounts{byGroup: make(map[string]int)}
	moved := credentialCounts{byGroup: make(map[string]int)}
	for id, identity := range snapshot.Identities {
		if identity.Kind != grouping.Credential || identity.State != grouping.Active {
			continue
		}
		counts := &stable
		if _, moving := changed[id]; moving {
			counts = &moved
		}
		counts.byGroup[identity.GroupID]++
		counts.total++
	}
	return stable, moved
}

// All moved credentials share a target. Aggregating their original groups avoids
// materializing the token/credential cross product, including for wildcard moves.
func credentialAccessChanges(snapshot grouping.Snapshot, target string, changed map[string]struct{}) []groupingapi.CredentialAccessChange {
	stable, moved := countCredentials(snapshot, changed)
	changes := make([]groupingapi.CredentialAccessChange, 0)
	for id, token := range snapshot.Identities {
		if token.Kind != grouping.Token || token.State != grouping.Active {
			continue
		}
		afterGroup := token.GroupID
		if _, moving := changed[id]; moving {
			afterGroup = target
		}
		change := tokenAccessChange(token, afterGroup, target, stable, moved)
		if change.AddedCount != 0 || change.RemovedCount != 0 {
			changes = append(changes, change)
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].TokenID < changes[j].TokenID })
	return changes
}

func tokenAccessChange(token grouping.Identity, after, target string, stable, moved credentialCounts) groupingapi.CredentialAccessChange {
	change := groupingapi.CredentialAccessChange{TokenID: token.ID,
		BeforeCount: stable.accessible(token.GroupID) + moved.accessible(token.GroupID),
		AfterCount:  stable.accessible(after)}
	intersection := stable.intersection(token.GroupID, after)
	if after == grouping.AllGroups || target == grouping.AllGroups || after == target {
		change.AfterCount += moved.total
		intersection += moved.accessible(token.GroupID)
	}
	change.AddedCount = change.AfterCount - intersection
	change.RemovedCount = change.BeforeCount - intersection
	return change
}
