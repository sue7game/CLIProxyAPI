package groupingadmin

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

// Initialize delegates explicit migration without activating grouping.
func (b *Backend) Initialize(ctx context.Context) (result groupingapi.Status, err error) {
	record := b.lifecycleAudit(0, groupingapi.Mutation{Operation: "initialize"})
	defer func() {
		if err == nil {
			record.Namespace, record.Revision = result.Namespace, result.Revision
		}
		record.Log(err == nil)
	}()
	if b == nil || ctx == nil || ctx.Err() != nil || b.options.Initialize == nil {
		return groupingapi.Status{}, groupingapi.ErrUnavailable
	}
	result, err = b.options.Initialize(ctx)
	if err != nil {
		return groupingapi.Status{}, publicError(err)
	}
	b.notify()
	return result, nil
}

// Apply executes one revision-checked operation and then notifies revocation hooks.
func (b *Backend) Apply(ctx context.Context, expected uint64, mutation groupingapi.Mutation) (groupingapi.ApplyResult, error) {
	if mutation.Operation == groupingapi.Activate || mutation.Operation == groupingapi.Rebind {
		return b.lifecycle(ctx, expected, mutation)
	}
	record := mutationAudit(expected, mutation)
	result, err := withLock(b, ctx, func() (groupingapi.ApplyResult, error) {
		snapshot, err := b.snapshot()
		if err != nil {
			return groupingapi.ApplyResult{}, err
		}
		auditSnapshot(&record, snapshot, mutation)
		if b.options.BeforeMutation != nil {
			if err := b.options.BeforeMutation(); err != nil {
				return groupingapi.ApplyResult{}, err
			}
		}
		return b.update(ctx, expected, mutation)
	})
	if err == nil {
		record.Revision = result.AppliedRevision
		if mutation.Operation == groupingapi.CreateGroup && result.Group != nil {
			record.LogicalIDs = []string{result.Group.ID}
		}
		b.notify()
	}
	record.Log(err == nil)
	return result, err
}

func (b *Backend) update(ctx context.Context, expected uint64, mutation groupingapi.Mutation) (groupingapi.ApplyResult, error) {
	result := groupingapi.ApplyResult{}
	snapshot, err := b.options.Store().Update(expected, func(snapshot *grouping.Snapshot) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch mutation.Operation {
		case groupingapi.CreateGroup:
			group, err := snapshot.CreateGroup(mutation.Name)
			if err != nil {
				return err
			}
			result.Group = &groupingapi.Group{ID: group.ID, Name: group.Name}
			return nil
		case groupingapi.RenameGroup:
			if err := snapshot.RenameGroup(mutation.ID, mutation.Name); err != nil {
				return err
			}
			group := snapshot.Groups[mutation.ID]
			result.Group = &groupingapi.Group{ID: group.ID, Name: group.Name}
			return nil
		case groupingapi.DeleteGroup:
			return snapshot.DeleteGroup(mutation.ID)
		case groupingapi.Bind:
			return applyBinding(snapshot, mutation.Binding)
		default:
			return groupingapi.ErrConflict
		}
	})
	if err != nil {
		return groupingapi.ApplyResult{}, err
	}
	result.AppliedRevision = snapshot.Revision
	return result, nil
}

func (b *Backend) lifecycle(ctx context.Context, expected uint64, mutation groupingapi.Mutation) (result groupingapi.ApplyResult, err error) {
	record := b.lifecycleAudit(expected, mutation)
	defer func() {
		if err == nil {
			record.Revision = result.AppliedRevision
		}
		record.Log(err == nil)
	}()
	if b == nil || ctx == nil || ctx.Err() != nil {
		return groupingapi.ApplyResult{}, groupingapi.ErrUnavailable
	}
	callback := b.options.Activation
	if mutation.Operation == groupingapi.Rebind {
		callback = b.options.Rebind
	}
	if callback == nil {
		return groupingapi.ApplyResult{}, groupingapi.ErrUnavailable
	}
	result, err = callback(ctx, expected, mutation)
	if err != nil {
		return groupingapi.ApplyResult{}, publicError(err)
	}
	b.notify()
	return result, nil
}
