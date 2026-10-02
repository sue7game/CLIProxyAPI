package management

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// deleteCredentialWithIdentity handles opt-in optimistic identity checks while the
// caller holds its config mutex. Legacy selectors are unchanged without a guard.
func (h *Handler) deleteCredentialWithIdentity(c *gin.Context, count int, identities func(int) []string, remove func(int), allowSet bool) bool {
	single, hasSingle := c.GetQuery("grouping-id")
	set, hasSet := c.GetQuery("grouping-ids")
	if !hasSingle && !hasSet {
		return false
	}
	if hasSingle == hasSet || hasSet && !allowSet || hasDeleteAlternativeSelector(c) {
		c.JSON(400, gin.H{"error": "invalid_identity_precondition", "message": "use index with exactly one supported grouping identity precondition"})
		return true
	}
	index, err := strconv.Atoi(c.Query("index"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_identity_precondition", "message": "an integer index is required with a grouping identity precondition"})
		return true
	}
	expected := []string{single}
	if hasSet {
		if err = json.Unmarshal([]byte(set), &expected); err != nil {
			c.JSON(400, gin.H{"error": "invalid_identity_precondition", "message": "grouping-ids must be a JSON array of UUIDs"})
			return true
		}
	}
	if index < 0 || index >= count || !sameCredentialIdentitySet(expected, identities(index)) {
		c.JSON(409, gin.H{"error": "credential_identity_changed", "message": "credential selection changed; refresh before deleting"})
		return true
	}
	remove(index)
	h.persistLocked(c)
	return true
}

func hasDeleteAlternativeSelector(c *gin.Context) bool {
	for _, key := range []string{"api-key", "name", "base-url", "all"} {
		if _, exists := c.GetQuery(key); exists {
			return true
		}
	}
	return false
}

func sameCredentialIdentitySet(expected, actual []string) bool {
	if len(expected) == 0 || len(expected) != len(actual) {
		return false
	}
	seen := make(map[uuid.UUID]bool, len(expected))
	for _, value := range expected {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || !strings.EqualFold(value, id.String()) || seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, value := range actual {
		id, err := uuid.Parse(value)
		if err != nil || !seen[id] {
			return false
		}
		delete(seen, id)
	}
	return len(seen) == 0
}

func (h *Handler) openAICompatibilityIdentities(index int) []string {
	entry := h.cfg.OpenAICompatibility[index]
	if len(entry.APIKeyEntries) == 0 {
		return []string{entry.GroupingID}
	}
	ids := make([]string, len(entry.APIKeyEntries))
	for i := range entry.APIKeyEntries {
		ids[i] = entry.APIKeyEntries[i].GroupingID
	}
	return ids
}
