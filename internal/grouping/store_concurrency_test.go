package grouping

import (
	"errors"
	"sync"
	"testing"
)

func TestStoreConcurrentReadersAndWriters(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	start := make(chan struct{})
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			<-start
			for range 100 {
				snapshot, err := store.Snapshot()
				if err != nil {
					t.Error(err)
					return
				}
				snapshot.Groups["private-copy"] = Group{Name: "unused"}
				_, err = store.Fingerprint("provider", "example-secret")
				if err != nil && !errors.Is(err, ErrRevision) {
					t.Error(err)
				}
			}
		})
	}
	close(start)
	for range 8 {
		before, _ := store.Snapshot()
		if _, err := store.Update(before.Revision, func(*Snapshot) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	readers.Wait()
}

func TestStoreHasherConcurrentClose(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	hasher, err := store.IdentityHasher()
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			<-start
			for range 100 {
				if _, err := hasher("provider", "secret"); err != nil && !errors.Is(err, ErrUnavailable) {
					t.Error(err)
				}
			}
		})
	}
	close(start)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
}
