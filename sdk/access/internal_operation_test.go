package access

import (
	"context"
	"testing"
)

func TestInternalOperationCannotLeakAcrossRequestAuthentication(t *testing.T) {
	internal := WithInternalOperation(context.Background(), InternalMaintenance)
	if _, ok := InternalOperationFromContext(internal); !ok {
		t.Fatal("explicit operation absent")
	}
	user := WithAuthenticatedPrincipal(internal, "provider", "test-subject")
	if _, ok := InternalOperationFromContext(user); ok {
		t.Fatal("user inherited internal scope")
	}
	missing := CopyAuthenticatedPrincipal(internal, context.Background())
	if _, ok := InternalOperationFromContext(missing); ok {
		t.Fatal("anonymous request inherited internal scope")
	}
	admin := WithInternalOperation(context.Background(), InternalManagement)
	copy := CopyAuthenticatedPrincipal(context.Background(), admin)
	if value, ok := InternalOperationFromContext(copy); !ok || value != InternalManagement {
		t.Fatal("authenticated administration lost scope")
	}
}

func TestInternalOperationRejectsUnknownAndUntypedMarkers(t *testing.T) {
	if _, ok := InternalOperationFromContext(WithInternalOperation(context.Background(), "unknown")); ok {
		t.Fatal("unknown operation accepted")
	}
	if _, ok := InternalOperationFromContext(context.WithValue(context.Background(), "internal-operation", "management")); ok {
		t.Fatal("untyped marker accepted")
	}
}
