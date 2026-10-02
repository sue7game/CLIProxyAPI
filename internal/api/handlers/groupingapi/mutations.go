package groupingapi

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

func (a *adapter) activation(c *gin.Context) {
	expected, ok := expectedRevision(c)
	if !ok {
		return
	}
	var request struct {
		Enabled                    *bool `json:"enabled"`
		ConfirmPermissionExpansion bool  `json:"confirm_permission_expansion"`
	}
	if !decodeObject(c, &request, "enabled", "confirm_permission_expansion") {
		return
	}
	if request.Enabled == nil {
		invalid(c, "The enabled field is required.")
		return
	}
	a.apply(c, expected, Mutation{Operation: Activate, Enabled: *request.Enabled,
		ConfirmPermissionExpansion: request.ConfirmPermissionExpansion})
}

func (a *adapter) createGroup(c *gin.Context) {
	a.writeGroup(c, CreateGroup)
}

func (a *adapter) renameGroup(c *gin.Context) {
	a.writeGroup(c, RenameGroup)
}

func (a *adapter) writeGroup(c *gin.Context, operation Operation) {
	expected, ok := expectedRevision(c)
	if !ok {
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if !decodeObject(c, &request, "name") {
		return
	}
	name := strings.TrimSpace(request.Name)
	if name == "" || utf8.RuneCountInString(name) > 64 || hasControl(name) {
		invalid(c, "The group name must contain 1 to 64 characters without control characters.")
		return
	}
	id := c.Param("id")
	if operation == RenameGroup && !validID(id) {
		invalid(c, "Invalid group ID.")
		return
	}
	a.apply(c, expected, Mutation{Operation: operation, ID: id, Name: name})
}

func (a *adapter) deleteGroup(c *gin.Context) {
	expected, ok := expectedRevision(c)
	if !ok || !emptyBody(c) {
		return
	}
	id := c.Param("id")
	if !validID(id) {
		invalid(c, "Invalid group ID.")
		return
	}
	a.apply(c, expected, Mutation{Operation: DeleteGroup, ID: id})
}

func (a *adapter) bindings(c *gin.Context) {
	expected, ok := expectedRevision(c)
	if !ok {
		return
	}
	request, ok := bindingRequest(c)
	if !ok {
		return
	}
	a.apply(c, expected, Mutation{Operation: Bind, Binding: request})
}

func (a *adapter) rebind(c *gin.Context) {
	expected, ok := expectedRevision(c)
	if !ok {
		return
	}
	var request struct {
		ID      string `json:"id"`
		Confirm bool   `json:"confirm"`
	}
	if !decodeObject(c, &request, "id", "confirm") {
		return
	}
	if !validID(request.ID) || !request.Confirm {
		invalid(c, "A valid ID and explicit confirm:true are required.")
		return
	}
	a.apply(c, expected, Mutation{Operation: Rebind, ID: request.ID, Confirm: true})
}

func bindingRequest(c *gin.Context) (BindingRequest, bool) {
	var request BindingRequest
	if !decodeObject(c, &request, "token_ids", "credential_ids", "group_id", "confirm_permission_expansion") {
		return request, false
	}
	count := len(request.TokenIDs) + len(request.CredentialIDs)
	if !validID(request.GroupID) || count == 0 || count > 500 {
		invalid(c, "A valid group_id and 1 to 500 identity IDs are required.")
		return request, false
	}
	seen := make(map[string]bool, count)
	for _, ids := range [][]string{request.TokenIDs, request.CredentialIDs} {
		for _, id := range ids {
			if !validID(id) || seen[id] {
				invalid(c, "Identity IDs must be valid and unique across the batch.")
				return request, false
			}
			seen[id] = true
		}
	}
	return request, true
}

func validID(id string) bool {
	if id == "" || len(id) > 128 || !utf8.ValidString(id) {
		return false
	}
	return !strings.ContainsFunc(id, func(char rune) bool {
		return unicode.IsSpace(char) || unicode.IsControl(char) || char == '/' || char == '\\'
	})
}

func hasControl(value string) bool {
	return strings.ContainsFunc(value, unicode.IsControl)
}
