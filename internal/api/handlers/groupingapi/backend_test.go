package groupingapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

type fakeBackend struct {
	mu          sync.Mutex
	revision    uint64
	err         error
	calls       int
	writes      int
	lastKind    string
	lastPreview BindingRequest
	lastCommand Mutation
	lastContext context.Context
	initialized bool
	enabled     bool
}

func newBackend() *fakeBackend {
	return &fakeBackend{revision: 7}
}

func (b *fakeBackend) status() Status {
	return Status{Revision: b.revision, Healthy: b.err == nil,
		Enabled: b.enabled, Initialized: b.initialized, Namespace: "test-namespace"}
}

func (b *fakeBackend) Status(ctx context.Context) (Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.lastContext = ctx
	return b.status(), b.err
}

func (b *fakeBackend) Initialize(ctx context.Context) (Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.lastContext = ctx
	if b.err != nil {
		return Status{}, b.err
	}
	b.initialized = true
	b.writes++
	return b.status(), nil
}

func (b *fakeBackend) Groups(ctx context.Context) (GroupsResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.lastContext = ctx
	return GroupsResult{Revision: b.revision, Groups: []Group{{ID: "all", Name: "All groups", System: true}}}, b.err
}

func (b *fakeBackend) Items(ctx context.Context, kind string) (ItemsResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.lastContext, b.lastKind = ctx, kind
	return ItemsResult{Revision: b.revision}, b.err
}

func (b *fakeBackend) Preview(ctx context.Context, request BindingRequest) (PreviewResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.lastContext, b.lastPreview = ctx, request
	return PreviewResult{Revision: b.revision,
		AffectedCount: len(request.TokenIDs) + len(request.CredentialIDs)}, b.err
}

func (b *fakeBackend) Apply(ctx context.Context, revision uint64, mutation Mutation) (ApplyResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.lastContext, b.lastCommand = ctx, mutation
	if b.err != nil {
		return ApplyResult{}, b.err
	}
	if revision != b.revision {
		return ApplyResult{}, ErrPrecondition
	}
	b.revision++
	b.writes++
	if mutation.Operation == Activate {
		b.enabled = mutation.Enabled
	}
	return ApplyResult{AppliedRevision: b.revision}, nil
}

func testRouter(backend Backend, middleware ...gin.HandlerFunc) *gin.Engine {
	router := gin.New()
	group := router.Group("/v8/management", middleware...)
	Register(group, backend)
	return router
}

func perform(router http.Handler, method, path, body, revision string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/v8/management/grouping"+path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if revision != "" {
		request.Header.Set("If-Match", revision)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}
