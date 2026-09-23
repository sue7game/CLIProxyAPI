package main

import (
	"slices"
	"testing"
	"time"
)

func TestSortCredentialViewsPlacesWeeklyEmptyCredentialsLastByResetTime(t *testing.T) {
	views := []credentialView{
		weeklyCredentialView("empty-unknown", "Empty unknown", 100, true, false, 0),
		weeklyCredentialView("empty-short-zulu", "Zulu", 8, true, true, 60),
		weeklyCredentialView("available-low", "Available", 1, false, true, 300),
		weeklyCredentialView("empty-long", "Empty long", 99, true, true, 120),
		weeklyCredentialView("unknown-high", "Unknown", 20, false, false, 0),
		weeklyCredentialView("empty-short-alpha-low", "Alpha", 8, true, true, 60),
		weeklyCredentialView("empty-short-alpha-high", "Alpha", 9, true, true, 60),
	}

	want := []string{
		"unknown-high",
		"available-low",
		"empty-short-alpha-high",
		"empty-short-alpha-low",
		"empty-short-zulu",
		"empty-long",
		"empty-unknown",
	}
	assertCredentialSortOrder(t, views, want)

	slices.Reverse(views)
	assertCredentialSortOrder(t, views, want)
}

func TestConfigurationViewUsesUnifiedConsecutive429Threshold(t *testing.T) {
	cfg := testConfig()
	cfg.Consecutive429Limit = 7

	view := configurationView(cfg)
	if view.Consecutive429Threshold != 7 || view.Quota429Threshold != 7 || view.Generic429Threshold != 7 {
		t.Fatalf("threshold views = %d/%d/%d, want 7/7/7", view.Consecutive429Threshold, view.Quota429Threshold, view.Generic429Threshold)
	}
}

func TestSortCredentialViewsKeepsAbsoluteWeeklyResetOrderAfterCountdownExpires(t *testing.T) {
	earlier := time.Date(2026, time.July, 27, 8, 0, 0, 0, time.UTC)
	later := earlier.Add(time.Hour)
	views := []credentialView{
		{
			AuthIndex:         "later-reset",
			Name:              "Later",
			EffectivePriority: 100,
			WeeklyQuota: &weeklyView{
				Empty:            true,
				RefreshKnown:     true,
				ResetTime:        &later,
				RemainingSeconds: 0,
			},
		},
		{
			AuthIndex:         "earlier-reset",
			Name:              "Earlier",
			EffectivePriority: 1,
			WeeklyQuota: &weeklyView{
				Empty:            true,
				RefreshKnown:     true,
				ResetTime:        &earlier,
				RemainingSeconds: 0,
			},
		},
	}

	assertCredentialSortOrder(t, views, []string{"earlier-reset", "later-reset"})
}

func weeklyCredentialView(authIndex, name string, priority int, empty, refreshKnown bool, remainingSeconds int64) credentialView {
	view := credentialView{
		AuthIndex:         authIndex,
		Name:              name,
		EffectivePriority: priority,
	}
	if empty || refreshKnown {
		view.WeeklyQuota = &weeklyView{
			Empty:            empty,
			RefreshKnown:     refreshKnown,
			RemainingSeconds: remainingSeconds,
		}
	}
	return view
}

func assertCredentialSortOrder(t *testing.T, views []credentialView, want []string) {
	t.Helper()
	sortCredentialViews(views)
	got := make([]string, len(views))
	for index := range views {
		got[index] = views[index].AuthIndex
	}
	if !slices.Equal(got, want) {
		t.Fatalf("credential order = %v, want %v", got, want)
	}
}
