package groupingadmin

import (
	"sort"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

// Group unions and cached sorted views avoid recomputing per-credential access
// for every token. Each index is private to one hypothetical policy preview.
type modelIndex struct {
	groups map[string]map[string]struct{}
	all    map[string]struct{}
	cache  map[string][]string
}

func newModelIndex() *modelIndex {
	return &modelIndex{groups: make(map[string]map[string]struct{}),
		all: make(map[string]struct{}), cache: make(map[string][]string)}
}

func (index *modelIndex) add(group string, models []string) {
	if index.groups[group] == nil {
		index.groups[group] = make(map[string]struct{})
	}
	for _, model := range models {
		index.groups[group][model] = struct{}{}
		index.all[model] = struct{}{}
	}
}

func (index *modelIndex) accessible(group string) []string {
	if models, ok := index.cache[group]; ok {
		return models
	}
	set := index.all
	if group != grouping.AllGroups {
		set = make(map[string]struct{}, len(index.groups[group])+len(index.groups[grouping.AllGroups]))
		for model := range index.groups[group] {
			set[model] = struct{}{}
		}
		for model := range index.groups[grouping.AllGroups] {
			set[model] = struct{}{}
		}
	}
	models := make([]string, 0, len(set))
	for model := range set {
		models = append(models, model)
	}
	sort.Strings(models)
	index.cache[group] = models
	return models
}

func modelDifference(before, after []string) ([]string, []string) {
	added, removed := make([]string, 0), make([]string, 0)
	for i, j := 0, 0; i < len(before) || j < len(after); {
		switch {
		case j == len(after) || i < len(before) && before[i] < after[j]:
			removed = append(removed, before[i])
			i++
		case i == len(before) || after[j] < before[i]:
			added = append(added, after[j])
			j++
		default:
			i++
			j++
		}
	}
	return added, removed
}
