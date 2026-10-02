package management

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

func (doc *configV8Document) mutate(c *gin.Context) bool {
	config.ProjectV8ConfigAliases(doc.root, strings.Join(doc.parts, "."))
	if c.Request.Method == http.MethodDelete {
		if len(doc.parts) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot_delete_config"})
			return false
		}
		if !deleteConfigV8Path(doc.root, doc.parts) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
			return false
		}
		return true
	}
	update := doc.readUpdate(c)
	if update == nil {
		return false
	}
	dst := configV8Path(doc.root, doc.parts)
	if dst == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_path"})
		return false
	}
	if c.Request.Method == http.MethodPatch {
		mergeConfigV8Patch(dst, update)
	} else {
		if dst.Kind == yaml.ScalarNode && update.Kind == yaml.ScalarNode {
			update.HeadComment, update.LineComment, update.FootComment = dst.HeadComment, dst.LineComment, dst.FootComment
		}
		*dst = *update
	}
	return true
}

func (doc *configV8Document) readUpdate(c *gin.Context) *yaml.Node {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_body"})
		return nil
	}
	if !doc.isYAML && !json.Valid(body) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
		return nil
	}
	var update yaml.Node
	if err = yaml.Unmarshal(body, &update); err != nil || len(update.Content) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_body"})
		return nil
	}
	if len(doc.parts) == 0 {
		if update.Content[0].Kind != yaml.MappingNode {
			c.JSON(http.StatusBadRequest, gin.H{"error": "config_must_be_object"})
			return nil
		}
		if err = config.NormalizeV8ConfigAliases(update.Content[0]); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_config"})
			return nil
		}
	}
	return update.Content[0]
}

func (doc *configV8Document) prepare(c *gin.Context, preserveCredentials bool) ([]byte, *config.Config) {
	if err := config.NormalizeV8ConfigAliases(doc.root); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_config"})
		return nil, nil
	}
	if !doc.isYAML && c.Request.Method != http.MethodDelete {
		preserveV8TURNSecrets(doc.root, doc.before)
	}
	if !validateV8ReadOnlyFields(c, doc.root, doc.before) {
		return nil, nil
	}
	data, err := yaml.Marshal(&doc.tree)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_config"})
		return nil, nil
	}
	parse := config.ParseConfigBytes
	if preserveCredentials {
		parse = config.ParseConfigBytesPreservingCredentials
	}
	next, err := parse(data)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid_config", "message": err.Error()})
		return nil, nil
	}
	if err = config.ValidateV8Config(data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_config", "message": err.Error()})
		return nil, nil
	}
	data, _, err = config.NormalizeConfigLayout(data, true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_config"})
		return nil, nil
	}
	return data, next
}

func validateV8ReadOnlyFields(c *gin.Context, root, before *yaml.Node) bool {
	for _, field := range []string{"credentials/concurrency/lifecycle-config-revision", "credentials/concurrency/observation-barrier-revision", "plugins/auth-revision"} {
		old := configV8Node(before, strings.Split(field, "/"))
		next := configV8Node(root, strings.Split(field, "/"))
		var a, b any
		if old != nil {
			_ = old.Decode(&a)
		}
		if next != nil {
			_ = next.Decode(&b)
		}
		if !reflect.DeepEqual(a, b) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "read_only_field", "field": field})
			return false
		}
	}
	return true
}
