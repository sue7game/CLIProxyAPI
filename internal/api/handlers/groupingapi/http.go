package groupingapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

const maxBodyBytes = 64 * 1024

func fail(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}

func backendError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrPrecondition):
		fail(c, http.StatusPreconditionFailed, "revision_mismatch", "Grouping state changed; reload before retrying.")
	case errors.Is(err, ErrConflict):
		fail(c, http.StatusConflict, "grouping_conflict", "The operation conflicts with grouping state or requires confirmation.")
	default:
		// Backend errors may include sensitive source material and must not be echoed.
		fail(c, http.StatusServiceUnavailable, "grouping_unavailable", "Grouping is unavailable; no successful write is reported.")
	}
}

func respond(c *gin.Context, revision uint64, body any) {
	c.Header("ETag", strconv.Quote(strconv.FormatUint(revision, 10)))
	c.JSON(http.StatusOK, body)
}

func expectedRevision(c *gin.Context) (uint64, bool) {
	values := c.Request.Header.Values("If-Match")
	if len(values) != 1 {
		fail(c, http.StatusPreconditionFailed, "revision_required", "A single quoted revision is required in If-Match.")
		return 0, false
	}
	value := strings.TrimSpace(values[0])
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		fail(c, http.StatusPreconditionFailed, "revision_required", "A single quoted revision is required in If-Match.")
		return 0, false
	}
	number := value[1 : len(value)-1]
	revision, err := strconv.ParseUint(number, 10, 64)
	if err != nil || revision == 0 || strconv.FormatUint(revision, 10) != number {
		fail(c, http.StatusPreconditionFailed, "revision_required", "If-Match must contain a positive canonical revision.")
		return 0, false
	}
	return revision, true
}

func decodeObject(c *gin.Context, target any, fields ...string) bool {
	contentType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || contentType != "application/json" {
		fail(c, http.StatusUnsupportedMediaType, "json_required", "Content-Type must be application/json.")
		return false
	}
	if c.Request.Body == nil {
		fail(c, http.StatusBadRequest, "invalid_body", "A JSON object is required.")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBodyBytes+1))
	if len(body) > maxBodyBytes {
		fail(c, http.StatusRequestEntityTooLarge, "body_too_large", "The request body exceeds 64 KiB.")
		return false
	}
	if err != nil || !utf8.Valid(body) || !validObject(body, fields) || json.Unmarshal(body, target) != nil {
		fail(c, http.StatusBadRequest, "invalid_body", "Invalid JSON object, field, or field type.")
		return false
	}
	return true
}

func validObject(body []byte, fields []string) bool {
	allowed := make(map[string]bool, len(fields))
	for _, field := range fields {
		allowed[field] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func emptyBody(c *gin.Context) bool {
	if c.Request.Body == nil {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1))
	if err != nil || len(body) != 0 {
		fail(c, http.StatusBadRequest, "invalid_body", "This operation does not accept a request body.")
		return false
	}
	return true
}
