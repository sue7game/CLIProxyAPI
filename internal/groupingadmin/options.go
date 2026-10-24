// Package groupingadmin implements grouping management against the durable store.
// Service lifecycle and source-identity verification remain callback responsibilities.
package groupingadmin

import (
	"context"
	"errors"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

// Label contains trusted, pre-redacted source metadata, never raw secrets.
type Label struct {
	Label  string
	Source string
}

// Options connects management operations to the service-owned lifecycle.
// Mutex, Store, and Enabled are required. The service must use the same lock for
// lifecycle changes, source updates, store replacement, and policy publication.
// Store, Enabled, Catalog, and ModelCatalog run under Mutex and must not reacquire
// that lock. Catalog callbacks read in-memory metadata without upstream requests.
// Other callbacks run without Mutex.
// Initialize, Activation, and Rebind own their transaction locks and must return
// only after a durable, runtime-effective result. Failure must not change policy.
// Initialize must never activate grouping or replace an existing installation.
// Activation must atomically check CAS and permission-expansion consent.
// Rebind must atomically check CAS, pending state, explicit confirmation, and the
// actual current source before restoring eligibility, preserving namespace, ID,
// and group. Store replacement must preserve the installation namespace and must
// never reuse a prior revision. Audit uses the CAS-bound base for lifecycle events.
// Missing callbacks deny use. Audit logs are operational, not a durable ledger.
// OnPolicyChanged runs synchronously after unlocking and before returning success.
// Notifications may arrive out of order: always reread current policy. The callback
// must enforce revocations before returning and may acquire Mutex itself.
// Services with long-lived connections must supply this callback.
type Options struct {
	Mutex       sync.Locker
	Store       func() *grouping.Store
	Enabled     func() bool
	Healthy     func() bool
	Initialized func() bool
	Catalog     func() map[string]Label
	// BeforeMutation runs under Mutex and must not reacquire it. It prevents a
	// normal policy mutation from interleaving with a staged source transaction.
	// Lifecycle callbacks must enforce the same exclusion themselves.
	BeforeMutation func() error
	// ModelCatalog is called once per valid preview with the original policy.
	// It maps stable credential UUIDs to public registered model IDs, with alias,
	// prefix, and disabled-source handling already applied by Service. Omitted
	// credentials have no registered models. A non-nil empty map is authoritative;
	// nil or error marks model preview unavailable while retaining credential data.
	// Production Service integrations must provide this callback.
	ModelCatalog    func(context.Context, grouping.Snapshot) (map[string][]string, error)
	Initialize      func(context.Context) (groupingapi.Status, error)
	Activation      func(context.Context, uint64, groupingapi.Mutation) (groupingapi.ApplyResult, error)
	Rebind          func(context.Context, uint64, groupingapi.Mutation) (groupingapi.ApplyResult, error)
	OnPolicyChanged func()
}

// Backend implements groupingapi.Backend without owning file migration or startup.
type Backend struct {
	options Options
}

var _ groupingapi.Backend = (*Backend)(nil)

// New validates the required shared-lock and service-state accessors.
func New(options Options) (*Backend, error) {
	if options.Mutex == nil || options.Store == nil || options.Enabled == nil {
		return nil, groupingapi.ErrUnavailable
	}
	return &Backend{options: options}, nil
}

func withLock[T any](backend *Backend, ctx context.Context, action func() (T, error)) (T, error) {
	var zero T
	if backend == nil || ctx == nil {
		return zero, groupingapi.ErrUnavailable
	}
	backend.options.Mutex.Lock()
	defer backend.options.Mutex.Unlock()
	if ctx.Err() != nil {
		return zero, groupingapi.ErrUnavailable
	}
	result, err := action()
	if err != nil {
		return zero, publicError(err)
	}
	return result, nil
}

func publicError(err error) error {
	switch {
	case errors.Is(err, groupingapi.ErrUnavailable), errors.Is(err, grouping.ErrUnavailable):
		return groupingapi.ErrUnavailable
	case errors.Is(err, groupingapi.ErrPrecondition), errors.Is(err, grouping.ErrRevision):
		return groupingapi.ErrPrecondition
	case errors.Is(err, groupingapi.ErrConflict), errors.Is(err, grouping.ErrConflict),
		errors.Is(err, grouping.ErrNotFound), errors.Is(err, grouping.ErrInvalid):
		return groupingapi.ErrConflict
	default:
		return groupingapi.ErrUnavailable
	}
}

func (b *Backend) notify() {
	if b.options.OnPolicyChanged != nil {
		b.options.OnPolicyChanged()
	}
}
