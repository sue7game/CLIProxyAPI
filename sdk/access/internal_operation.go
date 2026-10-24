package access

import "context"

type internalOperationKey struct{}

// InternalOperation names a trusted host operation, not a client identity.
type InternalOperation string

const (
	InternalMaintenance InternalOperation = "credential-maintenance"
	InternalManagement  InternalOperation = "management"
)

// WithInternalOperation grants a non-serializable scope at a trusted host boundary.
// Never call it based on request fields, plugin metadata, or missing authentication.
func WithInternalOperation(ctx context.Context, operation InternalOperation) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if operation != InternalMaintenance && operation != InternalManagement {
		operation = ""
	}
	return context.WithValue(ctx, internalOperationKey{}, operation)
}

// InternalOperationFromContext reads only the host-owned typed operation marker.
func InternalOperationFromContext(ctx context.Context) (InternalOperation, bool) {
	if ctx == nil {
		return "", false
	}
	operation, ok := ctx.Value(internalOperationKey{}).(InternalOperation)
	return operation, ok && (operation == InternalMaintenance || operation == InternalManagement)
}
