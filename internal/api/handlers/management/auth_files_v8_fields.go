package management

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// PatchAuthFileFieldsV8 preserves the upstream metadata editor while reserving
// permanent grouping identities for the transaction owner, never field edits.
func (h *Handler) PatchAuthFileFieldsV8(c *gin.Context) {
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	for name := range fields {
		root, _, _ := strings.Cut(strings.TrimSpace(name), ".")
		root = strings.TrimSpace(root)
		if root == "grouping_id" || root == "grouping-id" {
			c.JSON(http.StatusConflict, gin.H{"error": "credential_identity_immutable", "message": "permanent grouping identities cannot be changed through credential metadata"})
			return
		}
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	h.PatchAuthFileFields(c)
}
