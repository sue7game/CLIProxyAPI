package grouping

import "net/http"

// AccessError exposes a safe HTTP status without leaking identity information.
type AccessError struct {
	status  int
	message string
}

func (e *AccessError) Error() string { return e.message }

// StatusCode returns the status used by protocol-specific error adapters.
func (e *AccessError) StatusCode() int { return e.status }

var (
	ErrUnauthenticated = &AccessError{http.StatusUnauthorized, "grouping: authenticated identity is unavailable"}
	ErrDenied          = &AccessError{http.StatusForbidden, "grouping: credential is unavailable for this request"}
	ErrPolicyChanged   = &AccessError{http.StatusServiceUnavailable, "grouping: policy changed; retry the request"}
)

// AccessScope is an immutable, request-local authorization snapshot.
// All inputs are trusted server-side identity references, never client group names.
type AccessScope struct {
	namespace  string
	revision   uint64
	token      Binding
	rules      *Rules
	identities map[string]Identity
}

// BeginAccess resolves exactly one active token in an isolated policy snapshot.
func BeginAccess(snapshot Snapshot, provider, fingerprint string) (*AccessScope, error) {
	if provider == "" || fingerprint == "" {
		return nil, ErrUnauthenticated
	}
	if err := snapshot.Validate(); err != nil {
		return nil, ErrUnavailable
	}
	var token Binding
	for _, identity := range snapshot.Identities {
		if identity.Kind != Token || identity.Provider != provider || identity.Fingerprint != fingerprint {
			continue
		}
		if token.ID != "" || identity.State != Active {
			return nil, ErrUnauthenticated
		}
		token = identity.Binding
	}
	if token.ID == "" {
		return nil, ErrUnauthenticated
	}
	ids := make([]string, 0, len(snapshot.Groups))
	for id := range snapshot.Groups {
		ids = append(ids, id)
	}
	rules, err := NewRules(ids)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &AccessScope{snapshot.Namespace, snapshot.Revision, token, rules, snapshot.Clone().Identities}, nil
}

// Allows checks one source identity without locks, I/O, or mutable shared state.
func (s *AccessScope) Allows(id, provider, fingerprint string) bool {
	if s == nil || id == "" || provider == "" || fingerprint == "" {
		return false
	}
	identity, ok := s.identities[id]
	return ok && identity.Provider == provider && identity.Fingerprint == fingerprint &&
		s.rules.Allows(s.token, identity.Binding)
}

// AuthorizeUse refuses stale decisions, including otherwise-permitted changes.
// A new attempt must acquire a new scope rather than widening an old decision.
func (s *AccessScope) AuthorizeUse(current Snapshot, id, provider, fingerprint string) error {
	if s == nil || current.Namespace != s.namespace || current.Revision != s.revision {
		return ErrPolicyChanged
	}
	if !s.Allows(id, provider, fingerprint) {
		return ErrDenied
	}
	return nil
}
