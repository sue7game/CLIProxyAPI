package groupingapi

import (
	"sort"

	log "github.com/sirupsen/logrus"
)

// AuditGroupChange identifies a requested assignment, never source identity data.
// A failed event describes an attempt, not an applied change.
type AuditGroupChange struct {
	ID       string `json:"id"`
	OldGroup string `json:"old_group"`
	NewGroup string `json:"new_group"`
}

// AuditRecord is an allowlist of secret-free management audit metadata.
// Revision is the applied revision on success, or the requested CAS revision on
// failure (zero if unavailable). These operational logs are not a durable ledger.
type AuditRecord struct {
	Action             Operation
	Namespace          string
	Revision           uint64
	LogicalIDs         []string
	GroupChanges       []AuditGroupChange
	ConfirmationReason string
}

// Log emits a fixed success/failure message without arbitrary error or request data.
// Only canonical UUIDs, the reserved group "all", and fixed reason codes survive.
func (record AuditRecord) Log(success bool) {
	fields := log.Fields{"action": auditOperation(record.Action), "revision": record.Revision}
	if canonicalUUID(record.Namespace) {
		fields["namespace"] = record.Namespace
	}
	if ids := auditIDs(record.LogicalIDs); len(ids) != 0 {
		fields["logical_ids"] = ids
	}
	if changes := auditChanges(record.GroupChanges); len(changes) != 0 {
		fields["group_changes"] = changes
	}
	switch record.ConfirmationReason {
	case "permission_expansion", "disable_grouping", "identity_rebind":
		fields["confirmation_reason"] = record.ConfirmationReason
	}
	if success {
		log.WithFields(fields).Info("grouping management mutation succeeded")
	} else {
		log.WithFields(fields).Warn("grouping management mutation failed")
	}
}

func auditOperation(operation Operation) Operation {
	switch operation {
	case "initialize", Activate, CreateGroup, RenameGroup, DeleteGroup, Bind, Rebind:
		return operation
	default:
		return "unknown"
	}
}

func auditIDs(values []string) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		if canonicalUUID(value) {
			seen[value] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func auditChanges(values []AuditGroupChange) []AuditGroupChange {
	changes := make([]AuditGroupChange, 0, len(values))
	for _, change := range values {
		if canonicalUUID(change.ID) && auditGroup(change.OldGroup) && auditGroup(change.NewGroup) {
			changes = append(changes, change)
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].ID < changes[j].ID })
	return changes
}

func auditGroup(value string) bool {
	return value == "all" || canonicalUUID(value)
}
