package grouping

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"
)

// IdentityHasher captures a revision-bound calculator without disk I/O or locks.
// The returned function fails after policy replacement, close, or failed writes.
// It is safe for concurrent use, but is not a substitute for use-time authorization.
func (s *Store) IdentityHasher() (func(namespace, subject string) (string, error), error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	current, key := s.current.Load(), s.identityKey.Load()
	if current == nil || key == nil {
		return nil, ErrUnavailable
	}
	return func(namespace, subject string) (string, error) {
		if err := s.checkHashRevision(current); err != nil {
			return "", err
		}
		value, err := hashIdentity(key, namespace, subject)
		if err != nil {
			return "", err
		}
		if err := s.checkHashRevision(current); err != nil {
			return "", err
		}
		return value, nil
	}, nil
}

func (s *Store) checkHashRevision(expected *publishedPolicy) error {
	current := s.current.Load()
	if current == nil {
		return ErrUnavailable
	}
	if current != expected {
		return ErrRevision
	}
	return nil
}

func hashIdentity(key *[32]byte, namespace, subject string) (string, error) {
	if namespace == "" || subject == "" || !utf8.ValidString(namespace) || !utf8.ValidString(subject) {
		return "", ErrInvalid
	}
	payload, err := json.Marshal([]string{namespace, subject})
	if err != nil {
		return "", ErrInvalid
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
