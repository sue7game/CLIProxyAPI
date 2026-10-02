package groupingadmin

import (
	"context"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func (b *Backend) previewModels(ctx context.Context, snapshot grouping.Snapshot, target string, changed map[string]struct{}, result *groupingapi.PreviewResult) {
	result.ModelsScope = groupingapi.RegisteredModelCatalogScope
	result.ModelsUnavailableReason = "not_configured"
	if b.options.ModelCatalog == nil {
		return
	}
	// The callback sees the original policy, but cannot mutate the preview's copy.
	// One catalog is reused for both sides while the shared lock remains held.
	catalog, err := b.options.ModelCatalog(ctx, snapshot.Clone())
	result.ModelsUnavailableReason = "catalog_unavailable"
	if err != nil || catalog == nil {
		return
	}
	before, after, err := indexCatalogModels(snapshot, catalog, target, changed)
	if err != nil {
		return
	}
	result.ModelAccessChanges = modelAccessChanges(snapshot, target, changed, before, after)
	result.ModelsAvailable = true
	result.ModelsUnavailableReason = ""
}

func indexCatalogModels(snapshot grouping.Snapshot, catalog map[string][]string, target string, changed map[string]struct{}) (*modelIndex, *modelIndex, error) {
	before, after := newModelIndex(), newModelIndex()
	for id, credential := range snapshot.Identities {
		if credential.Kind != grouping.Credential || credential.State != grouping.Active {
			continue
		}
		models := catalog[id]
		for _, model := range models {
			if !validModelID(model) {
				return nil, nil, groupingapi.ErrUnavailable
			}
		}
		afterGroup := credential.GroupID
		if _, moving := changed[id]; moving {
			afterGroup = target
		}
		before.add(credential.GroupID, models)
		after.add(afterGroup, models)
	}
	return before, after, nil
}

func validModelID(model string) bool {
	return model != "" && utf8.ValidString(model) && strings.TrimSpace(model) == model &&
		!strings.ContainsFunc(model, unicode.IsControl)
}

func modelAccessChanges(snapshot grouping.Snapshot, target string, changed map[string]struct{}, before, after *modelIndex) []groupingapi.ModelAccessChange {
	changes := make([]groupingapi.ModelAccessChange, 0)
	deltas := make(map[[2]string]groupingapi.ModelAccessChange)
	for id, token := range snapshot.Identities {
		if token.Kind != grouping.Token || token.State != grouping.Active {
			continue
		}
		afterGroup := token.GroupID
		if _, moving := changed[id]; moving {
			afterGroup = target
		}
		key := [2]string{token.GroupID, afterGroup}
		change, exists := deltas[key]
		if !exists {
			change.Before, change.After = before.accessible(key[0]), after.accessible(key[1])
			change.Added, change.Removed = modelDifference(change.Before, change.After)
			deltas[key] = change
		}
		if len(change.Added) == 0 && len(change.Removed) == 0 {
			continue
		}
		change.TokenID = id
		change.Before, change.After = append([]string{}, change.Before...), append([]string{}, change.After...)
		change.Added, change.Removed = append([]string{}, change.Added...), append([]string{}, change.Removed...)
		changes = append(changes, change)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].TokenID < changes[j].TokenID })
	return changes
}
