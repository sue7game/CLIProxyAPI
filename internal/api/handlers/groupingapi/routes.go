package groupingapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type adapter struct {
	backend Backend
}

// Register mounts /grouping under an already authenticated management group.
// It does not create authentication exemptions or change parent middleware.
func Register(management *gin.RouterGroup, backend Backend) {
	a := &adapter{backend: backend}
	group := management.Group("/grouping")
	group.Use(auditMutations)
	group.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		if backend == nil {
			backendError(c, ErrUnavailable)
			return
		}
		c.Next()
	})
	group.GET("/status", a.status)
	group.POST("/initialize", a.initialize)
	group.PATCH("/activation", a.activation)
	group.GET("/groups", a.groups)
	group.POST("/groups", a.createGroup)
	group.PATCH("/groups/:id", a.renameGroup)
	group.DELETE("/groups/:id", a.deleteGroup)
	group.GET("/tokens", a.items(KindToken))
	group.GET("/credentials", a.items(KindCredential))
	group.PATCH("/bindings", a.bindings)
	group.POST("/preview", a.preview)
	group.POST("/bindings/rebind", a.rebind)
}

func (a *adapter) status(c *gin.Context) {
	result, err := a.backend.Status(c.Request.Context())
	if err != nil {
		backendError(c, err)
		return
	}
	respond(c, result.Revision, result)
}

func (a *adapter) initialize(c *gin.Context) {
	if !decodeObject(c, &struct{}{}) {
		return
	}
	c.Set(auditDelegatedKey, true)
	result, err := a.backend.Initialize(c.Request.Context())
	if err != nil {
		backendError(c, err)
		return
	}
	respond(c, result.Revision, struct {
		Status
		AppliedRevision uint64 `json:"applied_revision"`
	}{Status: result, AppliedRevision: result.Revision})
}

func (a *adapter) groups(c *gin.Context) {
	result, err := a.backend.Groups(c.Request.Context())
	if err != nil {
		backendError(c, err)
		return
	}
	if result.Groups == nil {
		result.Groups = []Group{}
	}
	respond(c, result.Revision, result)
}

func (a *adapter) preview(c *gin.Context) {
	request, ok := bindingRequest(c)
	if !ok {
		return
	}
	result, err := a.backend.Preview(c.Request.Context(), request)
	if err != nil {
		backendError(c, err)
		return
	}
	if result.CredentialAccessChanges == nil {
		result.CredentialAccessChanges = []CredentialAccessChange{}
	}
	result.ModelsScope = RegisteredModelCatalogScope
	if result.ModelsAvailable {
		result.ModelsUnavailableReason = ""
		if result.ModelAccessChanges == nil {
			result.ModelAccessChanges = []ModelAccessChange{}
		}
	} else {
		result.ModelAccessChanges = nil
		if result.ModelsUnavailableReason != "catalog_unavailable" {
			result.ModelsUnavailableReason = "not_configured"
		}
	}
	respond(c, result.Revision, result)
}

func (a *adapter) apply(c *gin.Context, expected uint64, mutation Mutation) {
	c.Set(auditDelegatedKey, true)
	result, err := a.backend.Apply(c.Request.Context(), expected, mutation)
	if err != nil {
		backendError(c, err)
		return
	}
	respond(c, result.AppliedRevision, result)
}

func invalid(c *gin.Context, message string) {
	fail(c, http.StatusBadRequest, "invalid_request", message)
}
