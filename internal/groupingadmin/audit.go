package groupingadmin

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func mutationAudit(expected uint64, mutation groupingapi.Mutation) groupingapi.AuditRecord {
	record := groupingapi.AuditRecord{Action: mutation.Operation, Revision: expected}
	switch mutation.Operation {
	case groupingapi.Bind:
		record.LogicalIDs = append(record.LogicalIDs, mutation.Binding.TokenIDs...)
		record.LogicalIDs = append(record.LogicalIDs, mutation.Binding.CredentialIDs...)
		if mutation.Binding.ConfirmPermissionExpansion {
			record.ConfirmationReason = "permission_expansion"
		}
	case groupingapi.Rebind:
		record.LogicalIDs = []string{mutation.ID}
		if mutation.Confirm {
			record.ConfirmationReason = "identity_rebind"
		}
	case groupingapi.Activate:
		if !mutation.Enabled && mutation.ConfirmPermissionExpansion {
			record.ConfirmationReason = "disable_grouping"
		}
	case groupingapi.RenameGroup, groupingapi.DeleteGroup:
		record.LogicalIDs = []string{mutation.ID}
	}
	return record
}

func auditSnapshot(record *groupingapi.AuditRecord, snapshot grouping.Snapshot, mutation groupingapi.Mutation) {
	record.Namespace = snapshot.Namespace
	if record.Revision != snapshot.Revision {
		return
	}
	seen := make(map[string]bool)
	for _, id := range record.LogicalIDs {
		identity, exists := snapshot.Identities[id]
		if !exists || seen[id] {
			continue
		}
		seen[id] = true
		target := identity.GroupID
		switch mutation.Operation {
		case groupingapi.Bind:
			target = mutation.Binding.GroupID
		case groupingapi.Rebind:
			// Rebind restores the same logical identity and preserves its group.
		default:
			continue
		}
		record.GroupChanges = append(record.GroupChanges, groupingapi.AuditGroupChange{
			ID: id, OldGroup: identity.GroupID, NewGroup: target,
		})
	}
}

func (b *Backend) lifecycleAudit(expected uint64, mutation groupingapi.Mutation) groupingapi.AuditRecord {
	record := mutationAudit(expected, mutation)
	if b == nil {
		return record
	}
	b.options.Mutex.Lock()
	defer b.options.Mutex.Unlock()
	snapshot, err := b.options.Store().Snapshot()
	if err == nil {
		auditSnapshot(&record, snapshot, mutation)
	}
	// An unavailable store has no trustworthy namespace or relationship to log.
	// The callback still owns health, CAS and consent checks; this is not preflight.
	return record
}
