package groupingadmin

import (
	"context"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

// Status reports service health without inventing a replacement for missing data.
func (b *Backend) Status(ctx context.Context) (groupingapi.Status, error) {
	return withLock(b, ctx, func() (groupingapi.Status, error) {
		result := groupingapi.Status{Enabled: b.options.Enabled()}
		if b.options.Initialized != nil {
			result.Initialized = b.options.Initialized()
		}
		store := b.options.Store()
		if store == nil {
			return result, nil
		}
		result.Initialized = true
		snapshot, err := store.Snapshot()
		if err != nil {
			return result, nil
		}
		result.Revision, result.Namespace = snapshot.Revision, snapshot.Namespace
		result.Healthy = b.options.Healthy == nil || b.options.Healthy()
		for _, identity := range snapshot.Identities {
			if identity.State == grouping.PendingRebind {
				result.PendingCount++
			}
		}
		return result, nil
	})
}

// Groups returns the built-in wildcard followed by deterministically sorted groups.
func (b *Backend) Groups(ctx context.Context) (groupingapi.GroupsResult, error) {
	return withLock(b, ctx, func() (groupingapi.GroupsResult, error) {
		snapshot, err := b.snapshot()
		if err != nil {
			return groupingapi.GroupsResult{}, err
		}
		groups := make([]groupingapi.Group, 0, len(snapshot.Groups))
		for _, group := range snapshot.Groups {
			groups = append(groups, groupingapi.Group{ID: group.ID, Name: group.Name})
		}
		sort.Slice(groups, func(i, j int) bool {
			if groups[i].Name == groups[j].Name {
				return groups[i].ID < groups[j].ID
			}
			return groups[i].Name < groups[j].Name
		})
		all := groupingapi.Group{ID: grouping.AllGroups, Name: "All groups", System: true}
		return groupingapi.GroupsResult{Revision: snapshot.Revision, Groups: append([]groupingapi.Group{all}, groups...)}, nil
	})
}

// Items lists identities of exactly one kind, including pending and retired records.
func (b *Backend) Items(ctx context.Context, kind string) (groupingapi.ItemsResult, error) {
	return withLock(b, ctx, func() (groupingapi.ItemsResult, error) {
		if kind != groupingapi.KindToken && kind != groupingapi.KindCredential {
			return groupingapi.ItemsResult{}, groupingapi.ErrConflict
		}
		snapshot, err := b.snapshot()
		if err != nil {
			return groupingapi.ItemsResult{}, err
		}
		items := make([]groupingapi.Item, 0)
		var catalog map[string]Label
		if b.options.Catalog != nil {
			catalog = b.options.Catalog()
		}
		for _, identity := range snapshot.Identities {
			if string(identity.Kind) != kind {
				continue
			}
			item, err := describe(identity, catalog[identity.ID])
			if err != nil {
				return groupingapi.ItemsResult{}, err
			}
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		groupIDs := make([]string, 0, len(snapshot.Groups))
		for id := range snapshot.Groups {
			groupIDs = append(groupIDs, id)
		}
		return groupingapi.ItemsResult{Revision: snapshot.Revision, Items: items, GroupIDs: groupIDs}, nil
	})
}

// Preview validates a batch and reports changed identities and group eligibility.
// Permission-expansion confirmation is deliberately not required for a read.
func (b *Backend) Preview(ctx context.Context, request groupingapi.BindingRequest) (groupingapi.PreviewResult, error) {
	return withLock(b, ctx, func() (groupingapi.PreviewResult, error) {
		snapshot, err := b.snapshot()
		if err != nil {
			return groupingapi.PreviewResult{}, err
		}
		change, err := prepareBinding(snapshot, request)
		if err != nil {
			return groupingapi.PreviewResult{}, err
		}
		result := groupingapi.PreviewResult{
			Revision: snapshot.Revision, AffectedCount: len(change.changed),
			PermissionExpansion:     expandsAccess(snapshot, request.GroupID, change.changed),
			CredentialAccessChanges: credentialAccessChanges(snapshot, request.GroupID, change.changed),
		}
		b.previewModels(ctx, snapshot, request.GroupID, change.changed, &result)
		return result, nil
	})
}

func (b *Backend) snapshot() (grouping.Snapshot, error) {
	if b.options.Healthy != nil && !b.options.Healthy() {
		return grouping.Snapshot{}, grouping.ErrUnavailable
	}
	return b.options.Store().Snapshot()
}

func describe(identity grouping.Identity, display Label) (groupingapi.Item, error) {
	item := groupingapi.Item{ID: identity.ID, Kind: string(identity.Kind),
		GroupID: identity.GroupID, State: string(identity.State), Provider: identity.Provider}
	if !validDisplay(display.Label, 256) || !validDisplay(display.Source, 512) {
		return groupingapi.Item{}, groupingapi.ErrUnavailable
	}
	item.Label, item.Source = display.Label, display.Source
	if item.Label == "" {
		item.Label = item.Provider + " " + item.ID[:8]
	}
	return item, nil
}

func validDisplay(value string, limit int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= limit &&
		!strings.ContainsFunc(value, unicode.IsControl)
}
