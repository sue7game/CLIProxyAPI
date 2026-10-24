package grouping

import (
	"errors"
	"sync"
	"testing"
)

func TestCheckIntegritySerializesWithPolicyWrites(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	var workers sync.WaitGroup
	start := make(chan struct{})
	workers.Go(func() {
		<-start
		for range 20 {
			if err := store.CheckIntegrity(); err != nil {
				t.Errorf("legitimate update failed integrity check: %v", err)
				return
			}
		}
	})
	close(start)
	for range 10 {
		snapshot, err := store.Snapshot()
		if err != nil {
			t.Error(err)
			break
		}
		if _, err := store.Update(snapshot.Revision, func(*Snapshot) error { return nil }); err != nil {
			t.Error(err)
			break
		}
	}
	workers.Wait()
	if err := store.CheckIntegrity(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckIntegritySerializesWithClose(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	var workers sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		workers.Go(func() {
			<-start
			if err := store.CheckIntegrity(); err != nil && !errors.Is(err, ErrUnavailable) {
				t.Errorf("unexpected close/check result: %v", err)
			}
		})
	}
	close(start)
	if err := store.Close(); err != nil {
		t.Error(err)
	}
	workers.Wait()
	assertStoreDisabled(t, store)
}
