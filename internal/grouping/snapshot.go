package grouping

import (
	"errors"
	"maps"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrInvalid     = errors.New("grouping: invalid policy data")
	ErrConflict    = errors.New("grouping: conflicting policy change")
	ErrNotFound    = errors.New("grouping: object not found")
	ErrRevision    = errors.New("grouping: policy revision changed")
	ErrUnavailable = errors.New("grouping: policy unavailable")
)

// Group is a concrete, immutable-ID group; the wildcard is not a stored group.
type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Identity binds one persistent source record independently of identical secrets.
// Fingerprint must be computed by the trusted source adapter, never the client.
type Identity struct {
	Binding
	Provider    string `json:"provider"`
	Fingerprint string `json:"fingerprint"`
}

// Snapshot is a versioned policy value. Published snapshots must not be mutated.
type Snapshot struct {
	SchemaVersion int                 `json:"schema_version"`
	Namespace     string              `json:"namespace"`
	Revision      uint64              `json:"revision"`
	Digest        string              `json:"digest"`
	Groups        map[string]Group    `json:"groups"`
	Identities    map[string]Identity `json:"identities"`
}

// NewSnapshot creates an explicit empty policy for an initialization operation.
func NewSnapshot() Snapshot {
	return Snapshot{SchemaVersion: 1, Namespace: uuid.NewString(), Revision: 1,
		Groups: make(map[string]Group), Identities: make(map[string]Identity)}
}

// Clone returns a copy that can be edited without changing the original policy.
func (s Snapshot) Clone() Snapshot {
	s.Groups = maps.Clone(s.Groups)
	s.Identities = maps.Clone(s.Identities)
	return s
}

// Validate rejects unknown schemas, invalid identities, and dangling references.
func (s Snapshot) Validate() error {
	if s.SchemaVersion != 1 || !validID(s.Namespace) || s.Revision == 0 || s.Groups == nil || s.Identities == nil {
		return ErrInvalid
	}
	names := make(map[string]struct{}, len(s.Groups))
	for id, group := range s.Groups {
		name, err := normalizedGroupName(group.Name)
		if err != nil || name != group.Name || id != group.ID || !validID(id) || group.CreatedAt.IsZero() || group.UpdatedAt.Before(group.CreatedAt) {
			return ErrInvalid
		}
		folded := foldedGroupName(name)
		if _, exists := names[folded]; exists {
			return ErrInvalid
		}
		names[folded] = struct{}{}
	}
	for id, identity := range s.Identities {
		if id != identity.ID || !s.validIdentity(identity) {
			return ErrInvalid
		}
	}
	return nil
}

func (s Snapshot) validIdentity(i Identity) bool {
	return validID(i.ID) && (i.Kind == Token || i.Kind == Credential) &&
		(i.State == Active || i.State == PendingRebind || i.State == Tombstone) &&
		validIdentityText(i.Provider) && validIdentityText(i.Fingerprint) && s.hasGroup(i.GroupID)
}

func validIdentityText(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func foldedGroupName(name string) string {
	return strings.Map(func(char rune) rune {
		minimum := char
		for next := unicode.SimpleFold(char); next != char; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		return minimum
	}, name)
}

func (s Snapshot) hasGroup(id string) bool {
	_, exists := s.Groups[id]
	return id == AllGroups || exists
}

func validID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

func normalizedGroupName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 64 || strings.EqualFold(name, AllGroups) || name == "所有分组" {
		return "", ErrInvalid
	}
	for _, char := range name {
		if unicode.IsControl(char) {
			return "", ErrInvalid
		}
	}
	return name, nil
}
