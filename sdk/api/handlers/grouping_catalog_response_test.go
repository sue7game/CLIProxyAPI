package handlers

import (
	"strings"
	"testing"
)

func TestGroupingCatalogInterceptorCannotWiden(t *testing.T) {
	for _, tt := range []struct{ original, intercepted string }{
		{`{"data":[{"id":"allowed"}],"first_id":"allowed","last_id":"allowed"}`, `{"data":[{"id":"blocked"},{"id":"allowed"}],"first_id":"blocked","last_id":"blocked"}`},
		{`{"models":[{"name":"models/allowed"}]}`, `{"models":[{"name":"models/blocked"},{"name":"models/allowed"}]}`},
		{`{"models":[{"slug":"allowed"}]}`, `{"models":[{"slug":"blocked"},{"slug":"allowed"}]}`},
	} {
		got, err := restrictModelListResponse([]byte(tt.original), []byte(tt.intercepted))
		if err != nil || strings.Contains(string(got), "blocked") || !strings.Contains(string(got), "allowed") {
			t.Fatalf("response=%s error=%v", got, err)
		}
	}
}

func TestGroupingCatalogMalformedInterceptorFailsClosed(t *testing.T) {
	for _, body := range []string{`not-json`, `{}`, `{"data":{}}`} {
		if _, err := restrictModelListResponse([]byte(`{"data":[]}`), []byte(body)); err == nil {
			t.Fatalf("accepted malformed response %s", body)
		}
	}
}
