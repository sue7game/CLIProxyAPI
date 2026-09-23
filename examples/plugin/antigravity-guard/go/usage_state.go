package main

func (s *stateStore) resetConsecutive429(authIndex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getLocked(authIndex).Usage.Consecutive429 = 0
}

func (s *stateStore) resetAllConsecutive429() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, state := range s.credentials {
		state.Usage.Consecutive429 = 0
		state.Codex.ConsecutiveUsageLimit = 0
	}
}
