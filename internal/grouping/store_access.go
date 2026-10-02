package grouping

type tokenReference struct {
	provider    string
	fingerprint string
}

// publishedPolicy owns validated maps that are never exposed to mutable callers.
type publishedPolicy struct {
	Snapshot
	rules  *Rules
	tokens map[tokenReference]Binding
}

func preparePublishedPolicy(snapshot Snapshot) (*publishedPolicy, error) {
	ids := make([]string, 0, len(snapshot.Groups))
	for id := range snapshot.Groups {
		ids = append(ids, id)
	}
	rules, err := NewRules(ids)
	if err != nil {
		return nil, ErrUnavailable
	}
	tokens := make(map[tokenReference]Binding)
	for _, identity := range snapshot.Identities {
		if identity.Kind != Token {
			continue
		}
		ref := tokenReference{identity.Provider, identity.Fingerprint}
		if _, exists := tokens[ref]; exists || identity.State != Active {
			// Any duplicate or inactive match makes the principal ambiguous.
			tokens[ref] = Binding{}
			continue
		}
		tokens[ref] = identity.Binding
	}
	return &publishedPolicy{snapshot, rules, tokens}, nil
}

// BeginAccess resolves a principal against the immutable, already validated
// publication without copying or scanning the complete identity catalog.
func (s *Store) BeginAccess(provider, fingerprint string) (*AccessScope, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	current := s.current.Load()
	if current == nil {
		return nil, ErrUnavailable
	}
	if provider == "" || fingerprint == "" {
		return nil, ErrUnauthenticated
	}
	token := current.tokens[tokenReference{provider, fingerprint}]
	if token.ID == "" {
		return nil, ErrUnauthenticated
	}
	return &AccessScope{current.Namespace, current.Revision, token, current.rules, current.Identities}, nil
}

// AuthorizeUse checks the current publication before dispatch without exposing
// its maps. A policy change, failed write, or closed store rejects an old scope.
func (s *Store) AuthorizeUse(scope *AccessScope, id, provider, fingerprint string) error {
	if s == nil {
		return ErrUnavailable
	}
	current := s.current.Load()
	if current == nil {
		return ErrUnavailable
	}
	return scope.AuthorizeUse(current.Snapshot, id, provider, fingerprint)
}
