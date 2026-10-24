package handlers

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type groupingV8ImagePolicy struct{ revoked atomic.Bool }

func (p *groupingV8ImagePolicy) BeginAttempt(ctx context.Context) (coreauth.CredentialAccessScope, error) {
	principal, exists := access.AuthenticatedPrincipalFromContext(ctx)
	if !exists || principal.Subject != "grouping-v8-image-token" || p.revoked.Load() {
		return nil, &coreauth.Error{HTTPStatus: http.StatusForbidden, Message: "image token denied"}
	}
	return p, nil
}

func (*groupingV8ImagePolicy) Allows(a *coreauth.Auth) bool {
	return a != nil && a.ID == "grouping-v8-image-allowed"
}

func (p *groupingV8ImagePolicy) AuthorizeUse(ctx context.Context, a *coreauth.Auth) error {
	if _, err := p.BeginAttempt(ctx); err != nil {
		return err
	}
	if !p.Allows(a) {
		return &coreauth.Error{HTTPStatus: http.StatusForbidden, Message: "image credential denied"}
	}
	return nil
}

func groupingV8ImageFixture(t *testing.T) (*BaseAPIHandler, *groupingV8ImagePolicy, *atomic.Int32) {
	t.Helper()
	manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
	policy, calls := &groupingV8ImagePolicy{}, &atomic.Int32{}
	manager.SetCredentialAccessPolicy(policy)
	check := func(a *coreauth.Auth, opts coreexecutor.Options) {
		calls.Add(1)
		if a == nil || a.ID != "grouping-v8-image-allowed" {
			t.Error("image execution escaped the permitted credential")
		}
		if opts.Metadata[coreexecutor.RequestPathMetadataKey] != "/v1/images/generations" {
			t.Error("image execution lost the v8 request path")
		}
	}
	manager.RegisterExecutor(&modelExecutionCaptureExecutor{
		provider: "grouping-v8-image",
		execute: func(_ context.Context, a *coreauth.Auth, _ coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
			check(a, opts)
			return coreexecutor.Response{Payload: []byte(`{"data":[]}`)}, nil
		},
		stream: func(_ context.Context, a *coreauth.Auth, _ coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
			check(a, opts)
			chunks := make(chan coreexecutor.StreamChunk, 1)
			chunks <- coreexecutor.StreamChunk{Payload: []byte("data: {\"data\":[]}\n\n")}
			close(chunks)
			return &coreexecutor.StreamResult{Chunks: chunks}, nil
		},
	})
	registerGroupingV8ImageCredentials(t, manager)
	return NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager), policy, calls
}

func registerGroupingV8ImageCredentials(t *testing.T, manager *coreauth.Manager) {
	t.Helper()
	for _, suffix := range []string{"allowed", "denied"} {
		id := "grouping-v8-image-" + suffix
		if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: "grouping-v8-image",
			Status: coreauth.StatusActive, Attributes: map[string]string{"grouping_id": id}}); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "grouping-v8-image", []*registry.ModelInfo{{ID: "gpt-image-2.5"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
}

func TestGroupingV8ImageExecutionPreservesPolicyAndRequestPath(t *testing.T) {
	for _, mode := range []string{"model", "model-stream", "protocol", "protocol-stream"} {
		t.Run(mode, func(t *testing.T) {
			h, policy, calls := groupingV8ImageFixture(t)
			ctx := access.WithAuthenticatedPrincipal(context.Background(), "test", "grouping-v8-image-token")
			if err := executeGroupingV8Image(h, ctx, mode); err != nil || calls.Load() != 1 {
				t.Fatalf("allowed image: error=%v calls=%d", err, calls.Load())
			}
			for _, denied := range []struct {
				ctx    context.Context
				status int
			}{
				{context.Background(), http.StatusForbidden},
				{WithPinnedAuthID(ctx, "grouping-v8-image-denied"), http.StatusServiceUnavailable},
			} {
				if err := executeGroupingV8Image(h, denied.ctx, mode); err == nil || err.StatusCode != denied.status {
					t.Fatalf("untrusted or wrong-group image: error=%v, want HTTP %d", err, denied.status)
				}
			}
			policy.revoked.Store(true)
			if err := executeGroupingV8Image(h, ctx, mode); err == nil || err.StatusCode != http.StatusForbidden {
				t.Fatalf("revoked image was accepted: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("denied image reached the executor: calls=%d", calls.Load())
			}
		})
	}
}

func executeGroupingV8Image(h *BaseAPIHandler, ctx context.Context, mode string) *interfaces.ErrorMessage {
	const path = "/v1/images/generations"
	body := []byte(`{"model":"gpt-image-2.5","prompt":"test image"}`)
	modelRequest := ModelExecutionRequest{EntryProtocol: "openai-image", ExitProtocol: "openai-image",
		Model: "gpt-image-2.5", Body: body, Path: path, Stream: mode == "model-stream"}
	protocolRequest := ProtocolExecutionRequest{EntryProtocol: "openai-image", ExitProtocol: "openai-image",
		Model: "gpt-image-2.5", Body: body, Path: path, Stream: mode == "protocol-stream"}
	switch mode {
	case "model":
		_, err := h.ExecuteModel(ctx, modelRequest)
		return err
	case "protocol":
		_, err := h.ExecuteProtocolWithAuthManager(ctx, protocolRequest)
		return err
	case "model-stream":
		stream, err := h.ExecuteModelStream(ctx, modelRequest)
		return drainGroupingImageStream(stream, err)
	default:
		stream, err := h.ExecuteProtocolStreamWithAuthManager(ctx, protocolRequest)
		return drainGroupingImageStream(stream, err)
	}
}

func drainGroupingImageStream(stream ModelExecutionStream, err *interfaces.ErrorMessage) *interfaces.ErrorMessage {
	if err != nil {
		return err
	}
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			return &interfaces.ErrorMessage{StatusCode: chunk.Err.StatusCode, Error: chunk.Err, Addon: chunk.Err.Headers}
		}
	}
	return nil
}

func TestGroupingV8ImageDirectPluginRoutingRemainsDenied(t *testing.T) {
	for _, mode := range []string{"model", "model-stream", "protocol", "protocol-stream"} {
		t.Run(mode, func(t *testing.T) {
			h, host := groupingPluginFixture()
			err := executeGroupingV8Image(h, context.Background(), mode)
			if err == nil || err.StatusCode != http.StatusForbidden || host.lastPluginID != "" {
				t.Fatalf("unverifiable image executor: error=%v plugin=%q", err, host.lastPluginID)
			}
		})
	}
}
