package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuthFilesV8FieldsCannotReassignGroupingIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handler{}
	router := gin.New()
	router.PATCH("/credentials/fields", h.PatchAuthFileFieldsV8)
	for _, field := range []string{"grouping_id", "grouping-id", " grouping_id .nested"} {
		response := httptest.NewRecorder()
		body := `{"name":"existing.json","` + field + `":"` + v8GroupingIDSecond + `"}`
		router.ServeHTTP(response, httptest.NewRequest("PATCH", "/credentials/fields", strings.NewReader(body)))
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "credential_identity_immutable") {
			t.Fatal("v8 metadata editor accepted permanent identity reassignment")
		}
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("PATCH", "/credentials/fields", strings.NewReader(`{"name":"existing.json","weight":2}`)))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("ordinary v8 metadata edit did not reach the original handler")
	}
}
