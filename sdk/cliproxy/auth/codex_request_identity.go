package auth

import (
	"context"
	"net/http"
)

type codexClientRequestContextKey struct{}

// Capture client identity before asynchronous work can outlive the pooled Gin context.
func snapshotCodexClientRequest(ctx context.Context, headers http.Header) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Value(codexClientRequestContextKey{}).(bool); ok {
		return ctx
	}
	return context.WithValue(ctx, codexClientRequestContextKey{}, IsCodexClientRequest(ctx, headers))
}
