package main

import "time"

type subscriptionState struct {
	Found     bool
	Summary   subscriptionSummary
	CheckedAt time.Time
	UpdatedAt time.Time
	LastError string
}

type subscriptionView struct {
	Found     bool       `json:"found"`
	Plan      string     `json:"plan,omitempty"`
	TierID    string     `json:"tier_id,omitempty"`
	TierName  string     `json:"tier_name,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	LastError string     `json:"last_error,omitempty"`
}

func (s *stateStore) recordSubscriptionResult(authIndex string, result subscriptionSummary, err error, checkedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := &s.getLocked(authIndex).Subscription
	state.CheckedAt = checkedAt
	if err != nil {
		state.LastError = err.Error()
		return
	}
	*state = subscriptionState{Found: true, Summary: result, CheckedAt: checkedAt, UpdatedAt: checkedAt}
}

func subscriptionViewFromState(state subscriptionState) *subscriptionView {
	view := &subscriptionView{
		Found:     state.Found,
		Plan:      state.Summary.Plan,
		TierID:    state.Summary.TierID,
		TierName:  state.Summary.TierName,
		LastError: state.LastError,
	}
	if !state.CheckedAt.IsZero() {
		checkedAt := state.CheckedAt
		view.CheckedAt = &checkedAt
	}
	if !state.UpdatedAt.IsZero() {
		updatedAt := state.UpdatedAt
		view.UpdatedAt = &updatedAt
	}
	return view
}
