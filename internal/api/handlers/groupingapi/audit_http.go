package groupingapi

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const auditDelegatedKey = "groupingapi.audit_delegated"

func auditMutations(c *gin.Context) {
	action := mutationAction(c)
	c.Next()
	if action != "" && !c.GetBool(auditDelegatedKey) && c.Writer.Status() >= http.StatusBadRequest {
		// Unvalidated input is deliberately absent, including URL IDs and headers.
		AuditRecord{Action: action}.Log(false)
	}
}

func mutationAction(c *gin.Context) Operation {
	path := c.FullPath()
	index := strings.LastIndex(path, "/grouping/")
	if index < 0 {
		return ""
	}
	switch c.Request.Method + " " + path[index+len("/grouping/"):] {
	case "POST initialize":
		return "initialize"
	case "PATCH activation":
		return Activate
	case "POST groups":
		return CreateGroup
	case "PATCH groups/:id":
		return RenameGroup
	case "DELETE groups/:id":
		return DeleteGroup
	case "PATCH bindings":
		return Bind
	case "POST bindings/rebind":
		return Rebind
	default:
		return ""
	}
}
