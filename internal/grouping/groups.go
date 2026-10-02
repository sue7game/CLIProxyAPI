package grouping

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// CreateGroup creates a concrete group, without changing any existing binding.
func (s *Snapshot) CreateGroup(name string) (Group, error) {
	name, err := s.availableGroupName(name, "")
	if err != nil {
		return Group{}, err
	}
	now := time.Now().UTC()
	group := Group{ID: uuid.NewString(), Name: name, CreatedAt: now, UpdatedAt: now}
	s.Groups[group.ID] = group
	return group, nil
}

// RenameGroup preserves its ID and all identity bindings.
func (s *Snapshot) RenameGroup(id, name string) error {
	if id == AllGroups {
		return ErrInvalid
	}
	group, exists := s.Groups[id]
	if !exists {
		return ErrNotFound
	}
	name, err := s.availableGroupName(name, id)
	if err != nil {
		return err
	}
	group.Name, group.UpdatedAt = name, time.Now().UTC()
	s.Groups[id] = group
	return nil
}

// DeleteGroup refuses to delete a group referenced by any registered identity.
func (s *Snapshot) DeleteGroup(id string) error {
	if id == AllGroups {
		return ErrInvalid
	}
	if _, exists := s.Groups[id]; !exists {
		return ErrNotFound
	}
	for _, identity := range s.Identities {
		if identity.GroupID == id {
			return ErrConflict
		}
	}
	delete(s.Groups, id)
	return nil
}

func (s *Snapshot) availableGroupName(name, exceptID string) (string, error) {
	name, err := normalizedGroupName(name)
	if err != nil || s.Groups == nil {
		return "", ErrInvalid
	}
	for id, group := range s.Groups {
		if id != exceptID && strings.EqualFold(group.Name, name) {
			return "", ErrConflict
		}
	}
	return name, nil
}

// Bind changes an entire batch after validating every referenced identity.
func (s *Snapshot) Bind(ids []string, groupID string) error {
	if len(ids) == 0 || !s.hasGroup(groupID) {
		return ErrInvalid
	}
	for _, id := range ids {
		identity, exists := s.Identities[id]
		if !exists {
			return ErrNotFound
		}
		if identity.State != Active {
			return ErrConflict
		}
	}
	for _, id := range ids {
		identity := s.Identities[id]
		identity.GroupID = groupID
		s.Identities[id] = identity
	}
	return nil
}
