package management

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

// ConfigV8ContextKey marks operations registered by the v8 API that save configuration.
const ConfigV8ContextKey = "management.config-v8"

type configV8Document struct {
	data   []byte
	tree   yaml.Node
	root   *yaml.Node
	before *yaml.Node
	parts  []string
	isYAML bool
}

// ConfigV8 serves persisted v8 configuration without migrating reads. Mutations
// retain the canonical YAML tree and enter the synchronous grouping transaction.
func (h *Handler) ConfigV8(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		h.getConfigV8(c)
		return
	}
	h.mutateConfigV8(c, nil)
}

// PatchAPIKeysV8 explicitly rotates a single token with its previous value. Both
// values are accepted only in the JSON body, never in selectors or logs.
func (h *Handler) PatchAPIKeysV8(c *gin.Context) {
	var body apiKeyPatch
	if err := c.ShouldBindJSON(&body); err != nil || body.Old == nil || body.New == nil || body.Index != nil || body.Value != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_body", "message": "provide old/new"})
		return
	}
	h.mutateConfigV8(c, &body)
}

func readConfigV8Document(c *gin.Context, source []byte) *configV8Document {
	data, _, err := config.NormalizeConfigLayout(source, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid_config"})
		return nil
	}
	doc := &configV8Document{data: data, isYAML: strings.HasSuffix(c.FullPath(), "/config.yaml")}
	if err = yaml.Unmarshal(data, &doc.tree); err != nil || len(doc.tree.Content) != 1 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid_config"})
		return nil
	}
	doc.root = doc.tree.Content[0]
	doc.before = cloneConfigV8Node(doc.root)
	if path := strings.Trim(c.Param("path"), "/"); path != "" {
		doc.parts = strings.Split(path, "/")
	}
	return doc
}

func (h *Handler) getConfigV8(c *gin.Context) {
	h.configApplyMu.Lock()
	defer h.configApplyMu.Unlock()
	h.mu.Lock()
	source, err := os.ReadFile(h.configFilePath)
	h.mu.Unlock()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read_failed"})
		return
	}
	doc := readConfigV8Document(c, source)
	if doc == nil {
		return
	}
	config.ProjectV8ConfigAliases(doc.root, strings.Join(doc.parts, "."))
	if !doc.isYAML {
		redactV8TURNSecrets(doc.root)
	}
	value := configV8Node(doc.root, doc.parts)
	if value == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("ETag", configV8ETag(source))
	if doc.isYAML {
		c.Data(http.StatusOK, "application/yaml; charset=utf-8", doc.data)
		return
	}
	var result any
	if err = value.Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "decode_failed"})
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encode_failed"})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", encoded)
}

func (h *Handler) mutateConfigV8(c *gin.Context, rotation *apiKeyPatch) {
	h.configApplyMu.Lock()
	defer h.configApplyMu.Unlock()
	snapshot := h.configV8Snapshot(c)
	if snapshot == nil {
		return
	}
	doc := readConfigV8Document(c, snapshot.source)
	if doc == nil {
		return
	}
	var tokenRotation *APIKeyRotation
	if rotation != nil {
		var err error
		tokenRotation, err = doc.rotateToken(snapshot.current, *rotation)
		if err != nil {
			writeConfigApplyError(c, err)
			return
		}
	} else if !doc.mutate(c) {
		return
	}
	data, next := doc.prepare(c, snapshot.hook != nil || snapshot.current.Grouping.Enabled)
	if next == nil {
		return
	}
	next.Home = snapshot.current.Home
	if h.commitConfigV8(c, snapshot, data, next, tokenRotation) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "config-version": 8})
	}
}

func (doc *configV8Document) rotateToken(current *config.Config, patch apiKeyPatch) (*APIKeyRotation, error) {
	next := current.CloneForRuntime()
	// A stale previous value must never append a new identity.
	next.Grouping.Enabled = true
	rotation, err := patch.apply(next)
	if err != nil {
		return nil, err
	}
	value := new(yaml.Node)
	if err = value.Encode(next.APIKeys); err != nil {
		return nil, err
	}
	dst := configV8Path(doc.root, []string{"access", "api-keys"})
	if dst == nil {
		return nil, &ConfigApplyError{400, "invalid_path", "invalid API token configuration path"}
	}
	*dst = *value
	return rotation, nil
}
