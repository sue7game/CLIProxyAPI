package grouping

import (
	"errors"
	"testing"
	"time"
)

func TestIdentityHasherInvalidatesOnRevisionAndClose(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	hasher, err := store.IdentityHasher()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := store.Fingerprint("provider", "secret")
	if err != nil {
		t.Fatal(err)
	}
	got, err := hasher("provider", "secret")
	if err != nil || got != expected {
		t.Fatalf("hasher differs from persistent identity: %v", err)
	}
	snapshot, _ := store.Snapshot()
	if _, err := store.Update(snapshot.Revision, func(*Snapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := hasher("provider", "secret"); !errors.Is(err, ErrRevision) {
		t.Fatal("cached hasher accepted a stale revision")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := hasher("provider", "secret"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cached hasher survived store shutdown")
	}
}

func TestIdentityHasherDoesNotWaitForPersist(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	entered, release := make(chan struct{}), make(chan struct{})
	store.writeSnapshot = func(Snapshot) error {
		close(entered)
		<-release
		return errors.New("injected failure")
	}
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		_, _ = store.Update(1, func(*Snapshot) error { return nil })
	}()
	defer func() { close(release); <-writeDone }()
	<-entered
	readDone := make(chan error, 1)
	go func() {
		hasher, err := store.IdentityHasher()
		if err == nil {
			_, err = hasher("provider", "secret")
		}
		if err == nil {
			_, err = store.Fingerprint("provider", "secret")
		}
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("identity calculation waited for the disk writer")
	}
}

func TestIdentityHasherRejectsLossyUTF8Encoding(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	for _, pair := range [][2]string{{"\xff", "secret"}, {"provider", "\xff"}, {"", "secret"}, {"provider", ""}} {
		if _, err := store.Fingerprint(pair[0], pair[1]); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid hash input was accepted")
		}
	}
	first, _ := store.Fingerprint("provider:a", "b")
	second, _ := store.Fingerprint("provider", "a:b")
	if first == second {
		t.Fatal("namespace and subject boundaries are ambiguous")
	}
}

func TestIdentityHasherInvalidatesAfterFailedWrite(t *testing.T) {
	store := initializeTestStore(t, privateTestDir(t))
	hasher, err := store.IdentityHasher()
	if err != nil {
		t.Fatal(err)
	}
	store.writeSnapshot = func(Snapshot) error { return errors.New("injected failure") }
	if _, err := store.Update(1, func(*Snapshot) error { return nil }); err == nil {
		t.Fatal("failed write returned success")
	}
	if _, err := hasher("provider", "secret"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cached calculator survived failed persistence")
	}
}
