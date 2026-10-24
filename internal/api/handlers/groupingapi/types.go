// Package groupingapi provides an HTTP adapter for credential grouping management.
// Its routes must be mounted inside the existing authenticated management group.
package groupingapi

import (
	"context"
	"errors"
)

var (
	ErrConflict     = errors.New("grouping conflict")
	ErrPrecondition = errors.New("grouping revision mismatch")
	ErrUnavailable  = errors.New("grouping unavailable")
)

const (
	KindToken      = "token"
	KindCredential = "credential"
)

// Backend implements grouping lifecycle, reads, and atomic mutations.
// Apply must atomically check health, revision, business rules, and permission
// expansion consent before writing. Failure must leave all state unchanged.
// Initialize must only initialize state, never enable grouping, and must refuse
// to recreate missing or damaged state belonging to an existing installation.
// Returned labels and sources must be sanitized and must never contain secrets.
// Preview must read a consistent snapshot without changing state.
// Initialize and Apply implementations must audit successes and failures; the HTTP
// adapter audits only requests rejected before delegation, without untrusted data.
// Wrap ErrConflict, ErrPrecondition, or ErrUnavailable to select an HTTP error;
// unrecognized errors also fail closed with HTTP 503 and no exposed details.
type Backend interface {
	Status(context.Context) (Status, error)
	Initialize(context.Context) (Status, error)
	Groups(context.Context) (GroupsResult, error)
	Items(context.Context, string) (ItemsResult, error)
	Preview(context.Context, BindingRequest) (PreviewResult, error)
	Apply(context.Context, uint64, Mutation) (ApplyResult, error)
}

// Status reports initialization, activation, and current runtime health.
type Status struct {
	Enabled      bool   `json:"enabled"`
	Initialized  bool   `json:"initialized"`
	Revision     uint64 `json:"revision"`
	Namespace    string `json:"namespace"`
	Healthy      bool   `json:"healthy"`
	PendingCount int    `json:"pending_count"`
}

// Group is the public, secret-free representation of a group.
type Group struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	System bool   `json:"system,omitempty"`
}

// GroupsResult contains groups from one consistent revision, including all.
type GroupsResult struct {
	Revision uint64  `json:"revision"`
	Groups   []Group `json:"groups"`
}

// Item contains only safe display data, not credentials or fingerprints.
type Item struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	GroupID  string `json:"group_id"`
	State    string `json:"state"`
	Provider string `json:"provider"`
	Label    string `json:"label"`
	Source   string `json:"source,omitempty"`
}

// ItemsResult contains identities from one consistent revision.
type ItemsResult struct {
	Revision   uint64           `json:"revision"`
	Items      []Item           `json:"items"`
	Pagination *ItemsPagination `json:"pagination,omitempty"`
	// GroupIDs is the complete concrete group catalog from the same snapshot.
	// It is internal metadata for accessible filtering; nil means unsupported.
	GroupIDs []string `json:"-"`
}

// ItemsPagination describes a page of the filtered, ID-sorted snapshot.
type ItemsPagination struct {
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// BindingRequest assigns selected identities to a group or previews that change.
type BindingRequest struct {
	TokenIDs                   []string `json:"token_ids,omitempty"`
	CredentialIDs              []string `json:"credential_ids,omitempty"`
	GroupID                    string   `json:"group_id"`
	ConfirmPermissionExpansion bool     `json:"confirm_permission_expansion,omitempty"`
}

// PreviewResult describes policy eligibility against a registered model catalog,
// not runtime quota, cooldown, health, or traffic outcomes.
type PreviewResult struct {
	Revision                uint64                   `json:"revision"`
	AffectedCount           int                      `json:"affected_count"`
	PermissionExpansion     bool                     `json:"permission_expansion"`
	CredentialAccessChanges []CredentialAccessChange `json:"credential_access_changes"`
	ModelsAvailable         bool                     `json:"models_available"`
	ModelsScope             string                   `json:"models_scope"`
	ModelsUnavailableReason string                   `json:"models_unavailable_reason,omitempty"`
	ModelAccessChanges      []ModelAccessChange      `json:"model_access_changes"`
}

// RegisteredModelCatalogScope limits model preview to public registered IDs.
const RegisteredModelCatalogScope = "registered_model_catalog"

// ModelAccessChange describes model unions for an active logical token.
// Only changed unions appear. Each list is sorted, unique, and non-nil.
type ModelAccessChange struct {
	TokenID string   `json:"token_id"`
	Before  []string `json:"before"`
	After   []string `json:"after"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// CredentialAccessChange counts active credentials allowed for one active token.
// Only tokens gaining or losing eligibility appear, including unselected tokens.
// AddedCount and RemovedCount are set differences, not a difference of totals.
type CredentialAccessChange struct {
	TokenID      string `json:"token_id"`
	BeforeCount  int    `json:"before_count"`
	AfterCount   int    `json:"after_count"`
	AddedCount   int    `json:"added_count"`
	RemovedCount int    `json:"removed_count"`
}

// Operation identifies a validated management command.
type Operation string

const (
	Activate    Operation = "activation"
	CreateGroup Operation = "create_group"
	RenameGroup Operation = "rename_group"
	DeleteGroup Operation = "delete_group"
	Bind        Operation = "bindings"
	Rebind      Operation = "rebind"
)

// Mutation carries a validated command; unused fields have their zero values.
// Bind uses Binding. Activate uses Enabled and ConfirmPermissionExpansion.
// Rebind uses ID and Confirm, which the adapter requires to be true.
type Mutation struct {
	Operation                  Operation
	ID                         string
	Name                       string
	Enabled                    bool
	ConfirmPermissionExpansion bool
	Binding                    BindingRequest
	Confirm                    bool
}

// ApplyResult is returned only after the mutation is effective in the runtime.
type ApplyResult struct {
	AppliedRevision uint64 `json:"applied_revision"`
	Group           *Group `json:"group,omitempty"`
	Enabled         *bool  `json:"enabled,omitempty"`
}
