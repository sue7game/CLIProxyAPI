package cliproxy

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher"
)

func completedBatchUpdate(t *testing.T, service *Service, first, second watcher.AuthUpdate) watcher.AuthUpdate {
	t.Helper()
	firstDone := service.authRegistrationWaitCh(first.ID)
	secondDone := service.authRegistrationWaitCh(second.ID)
	if firstDone == nil {
		return first
	}
	if secondDone == nil {
		return second
	}
	select {
	case <-firstDone:
		return first
	case <-secondDone:
		return second
	case <-time.After(2 * time.Second):
		t.Fatal("unblocked batch source did not finish registration")
		return watcher.AuthUpdate{}
	}
}
