package access

import (
	"context"
	"testing"
)

func TestAuthenticatedPrincipalContext(t *testing.T) {
	ctx := WithAuthenticatedPrincipal(context.Background(), "issuer", "test-subject")
	got, ok := AuthenticatedPrincipalFromContext(ctx)
	if !ok || got.Provider != "issuer" || got.Subject != "test-subject" {
		t.Fatalf("unexpected authenticated principal: present=%v", ok)
	}
	if _, ok := AuthenticatedPrincipalFromContext(context.WithValue(context.Background(), "principal", got)); ok {
		t.Fatal("string-key metadata forged a trusted principal")
	}
	for _, invalid := range []context.Context{nil, context.Background(), WithAuthenticatedPrincipal(ctx, "", "subject"), WithAuthenticatedPrincipal(ctx, "issuer", "")} {
		if _, ok := AuthenticatedPrincipalFromContext(invalid); ok {
			t.Fatal("missing identity retained or acquired authorization")
		}
	}
}

func TestCopyAuthenticatedPrincipalOverridesParent(t *testing.T) {
	parent := WithAuthenticatedPrincipal(context.Background(), "other", "other-subject")
	request := WithAuthenticatedPrincipal(context.Background(), "request", "request-subject")
	ctx := CopyAuthenticatedPrincipal(parent, request)
	got, ok := AuthenticatedPrincipalFromContext(ctx)
	if !ok || got.Provider != "request" {
		t.Fatal("request authentication did not override parent identity")
	}
	ctx = CopyAuthenticatedPrincipal(parent, context.Background())
	if _, ok := AuthenticatedPrincipalFromContext(ctx); ok {
		t.Fatal("unauthenticated request inherited a parent identity")
	}
}
