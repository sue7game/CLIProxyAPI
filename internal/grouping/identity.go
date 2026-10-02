package grouping

// Register adds a previously persisted source identity without merging secrets.
// Re-registering an ID is a conflict, even when the source fingerprint matches.
func (s *Snapshot) Register(identity Identity) error {
	if s.Identities == nil || !s.validIdentity(identity) {
		return ErrInvalid
	}
	if _, exists := s.Identities[identity.ID]; exists {
		return ErrConflict
	}
	s.Identities[identity.ID] = identity
	return nil
}

// ReplaceIdentity performs an explicit, compare-and-swap source replacement.
// The logical identity, role, provider and group never change during a rotation.
func (s *Snapshot) ReplaceIdentity(id, oldFingerprint, newFingerprint string) error {
	identity, exists := s.Identities[id]
	if !exists {
		return ErrNotFound
	}
	if !validIdentityText(newFingerprint) || !validIdentityText(oldFingerprint) {
		return ErrInvalid
	}
	if identity.Fingerprint != oldFingerprint || identity.State == Tombstone {
		return ErrConflict
	}
	identity.Fingerprint, identity.State = newFingerprint, Active
	s.Identities[id] = identity
	return nil
}

// SetIdentityState quarantines or retires a record without losing its group.
// Restoring access requires an explicit validated ReplaceIdentity operation.
func (s *Snapshot) SetIdentityState(id string, state RegistrationState) error {
	if state != PendingRebind && state != Tombstone {
		return ErrInvalid
	}
	identity, exists := s.Identities[id]
	if !exists {
		return ErrNotFound
	}
	if identity.State == Tombstone && state != Tombstone {
		return ErrConflict
	}
	identity.State = state
	s.Identities[id] = identity
	return nil
}
