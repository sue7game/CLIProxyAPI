// Package grouping provides credential and token group policy independently of
// request handlers, credential schedulers, and provider executors.
package grouping

// AllGroups is the reserved wildcard scope, not a user-created group identifier.
const AllGroups = "all"

// ObjectKind identifies the role of an object in an authorization decision.
type ObjectKind string

const (
	Token      ObjectKind = "token"
	Credential ObjectKind = "credential"
)

// RegistrationState determines whether an identity is eligible for authorization.
type RegistrationState string

const (
	Active        RegistrationState = "active"
	PendingRebind RegistrationState = "pending_rebind"
	Tombstone     RegistrationState = "tombstone"
)

// Binding describes a registered logical identity, never a raw authentication key.
// Only a trusted identity registry may supply bindings for authorization.
type Binding struct {
	ID      string            `json:"id"`
	Kind    ObjectKind        `json:"kind"`
	GroupID string            `json:"group_id"`
	State   RegistrationState `json:"state"`
}
