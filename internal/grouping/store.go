package grouping

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// Store owns a single-writer policy directory and publishes immutable snapshots.
type Store struct {
	mu            sync.Mutex
	dir           string
	dirInfo       os.FileInfo
	lock          *os.File
	key           []byte
	identityKey   atomic.Pointer[[32]byte]
	current       atomic.Pointer[publishedPolicy]
	writeSnapshot func(Snapshot) error
}

// InitializeStore explicitly creates a policy; it never replaces existing data.
func InitializeStore(dir string, initial Snapshot) (*Store, error) {
	if err := initial.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, ErrUnavailable
	}
	store, err := lockStore(dir)
	if err != nil {
		return nil, err
	}
	if err := store.initialize(initial.Clone()); err != nil {
		return nil, errors.Join(publicStoreError(err), store.Close())
	}
	return store, nil
}

func (s *Store) initialize(initial Snapshot) error {
	for _, name := range []string{"identity.key", "policy.json"} {
		if _, err := os.Lstat(filepath.Join(s.dir, name)); !errors.Is(err, os.ErrNotExist) {
			return ErrConflict
		}
	}
	s.key = make([]byte, 32)
	if _, err := rand.Read(s.key); err != nil {
		return fmt.Errorf("grouping: generate identity key: %w", err)
	}
	if err := atomicPolicyWrite(s.dir, "identity.key", s.key); err != nil {
		return err
	}
	if err := sealSnapshot(&initial); err != nil {
		return err
	}
	if err := s.writeSnapshot(initial); err != nil {
		return err
	}
	return s.publishLoaded(initial)
}

// OpenStore loads an existing policy and key without initializing missing data.
func OpenStore(dir string) (*Store, error) {
	store, err := lockStore(dir)
	if err != nil {
		return nil, err
	}
	if err := store.load(); err != nil {
		return nil, errors.Join(err, store.Close())
	}
	return store, nil
}

func lockStore(dir string) (*Store, error) {
	dir, info, err := checkedPolicyDirectory(dir)
	if err != nil {
		return nil, err
	}
	lock, err := acquirePolicyLock(filepath.Join(dir, ".writer.lock"))
	if err != nil {
		return nil, ErrUnavailable
	}
	s := &Store{dir: dir, dirInfo: info, lock: lock}
	s.writeSnapshot = s.persist
	return s, nil
}

// Snapshot returns an isolated management copy, or fails after close/write error.
func (s *Store) Snapshot() (Snapshot, error) {
	if s == nil {
		return Snapshot{}, ErrUnavailable
	}
	current := s.current.Load()
	if current == nil {
		return Snapshot{}, ErrUnavailable
	}
	return current.Clone(), nil
}

// Update validates and persists one atomic change before making it visible.
// Any uncertain disk write disables reads until the store is reopened safely.
func (s *Store) Update(expected uint64, change func(*Snapshot) error) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.current.Load()
	if current == nil {
		return Snapshot{}, ErrUnavailable
	}
	if expected != current.Revision {
		return Snapshot{}, ErrRevision
	}
	if change == nil || expected == math.MaxUint64 {
		return Snapshot{}, ErrInvalid
	}
	if err := s.checkStorage(&current.Snapshot); err != nil {
		s.current.Store(nil)
		return Snapshot{}, ErrUnavailable
	}
	next := current.Clone()
	if err := change(&next); err != nil {
		return Snapshot{}, err
	}
	if next.Namespace != current.Namespace || next.Revision != current.Revision {
		return Snapshot{}, ErrInvalid
	}
	next.Revision++
	if err := next.Validate(); err != nil {
		return Snapshot{}, err
	}
	if err := sealSnapshot(&next); err != nil {
		return Snapshot{}, err
	}
	published, err := preparePublishedPolicy(next.Clone())
	if err != nil {
		return Snapshot{}, err
	}
	if err := s.writeSnapshot(next); err != nil {
		s.current.Store(nil)
		return Snapshot{}, ErrUnavailable
	}
	s.current.Store(published)
	return next.Clone(), nil
}

func publicStoreError(err error) error {
	for _, safe := range []error{ErrInvalid, ErrConflict, ErrUnavailable} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return ErrUnavailable
}

// Fingerprint derives a namespaced identity without storing its raw secret.
func (s *Store) Fingerprint(namespace, subject string) (string, error) {
	hasher, err := s.IdentityHasher()
	if err != nil {
		return "", err
	}
	return hasher(namespace, subject)
}

// Close disables policy reads and releases the OS writer lock.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current.Store(nil)
	s.identityKey.Store(nil)
	clear(s.key)
	s.key = nil
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
