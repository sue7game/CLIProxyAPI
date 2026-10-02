package grouping

// CheckIntegrity verifies the complete backing policy under the writer lock.
// It performs disk I/O and is intended for background monitoring, not requests.
// Failure permanently disables this store instance; recovery requires reopening.
func (s *Store) CheckIntegrity() error {
	if s == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.current.Load()
	if current == nil {
		return ErrUnavailable
	}
	if err := s.checkStorage(&current.Snapshot); err != nil {
		s.current.Store(nil)
		return ErrUnavailable
	}
	return nil
}
