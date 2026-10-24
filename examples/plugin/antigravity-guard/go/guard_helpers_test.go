package main

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type blockingQuotaHost struct {
	*fakeHost
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type staleWeeklyCASHost struct {
	*fakeHost
	priority int
	once     sync.Once
}

type guardConfigHolder struct {
	mu    sync.RWMutex
	value guardConfig
}

func (h *guardConfigHolder) load() guardConfig {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.value
}

func (h *guardConfigHolder) updateStrategy(action string, priority int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.value.Action = action
	h.value.TemporaryPriority = priority
}

func (h *blockingQuotaHost) Request(request hostAuthRequest) (hostAuthResponse, error) {
	h.once.Do(func() { close(h.entered) })
	<-h.release
	return h.fakeHost.Request(request)
}

func (h *staleWeeklyCASHost) SetRuntimeOverride(request runtimeOverrideRequest) (runtimeOverrideResponse, error) {
	if request.IfRevisions != nil {
		h.once.Do(func() {
			_, _ = h.fakeHost.SetRuntimeOverride(runtimeOverrideRequest{
				AuthIndex: request.AuthIndex,
				Priority:  &h.priority,
			})
		})
	}
	return h.fakeHost.SetRuntimeOverride(request)
}

func quotaGuardHost(authIndex string, serverNow, reset time.Time, remaining float64) *fakeHost {
	body := fmt.Sprintf(
		`{"groups":[{"displayName":"Gemini models","buckets":[{"window":"weekly","remainingFraction":%g,"resetTime":"%s"}]}]}`,
		remaining,
		reset.Format(time.RFC3339Nano),
	)
	return &fakeHost{
		auths: []hostAuthEntry{quotaGuardAuth(authIndex)},
		requestResponse: hostAuthResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Date": []string{serverNow.Format(http.TimeFormat)}},
			Body:       []byte(body),
		},
	}
}

func quotaWindowGuardHost(
	authIndex string,
	serverNow, fiveHourReset, weeklyReset time.Time,
	fiveHourRemaining, weeklyRemaining float64,
) *fakeHost {
	body := fmt.Sprintf(
		`{"groups":[{"displayName":"Gemini models","buckets":[`+
			`{"window":"five_hour","remainingFraction":%g,"resetTime":"%s"},`+
			`{"window":"weekly","remainingFraction":%g,"resetTime":"%s"}`+
			`]}]}`,
		fiveHourRemaining,
		fiveHourReset.Format(time.RFC3339Nano),
		weeklyRemaining,
		weeklyReset.Format(time.RFC3339Nano),
	)
	return &fakeHost{
		auths: []hostAuthEntry{quotaGuardAuth(authIndex)},
		requestResponse: hostAuthResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Date": []string{serverNow.Format(http.TimeFormat)}},
			Body:       []byte(body),
		},
	}
}

func quotaGuardAuth(authIndex string) hostAuthEntry {
	entry := testAntigravityAuth(authIndex, 14)
	entry.ProjectID = "project-123"
	return entry
}

func quota429Record(authIndex string) pluginapi.UsageRecord {
	return pluginapi.UsageRecord{
		Provider:  "antigravity",
		AuthIndex: authIndex,
		Generate:  true,
		Failed:    true,
		Failure: pluginapi.UsageFailure{
			StatusCode: http.StatusTooManyRequests,
			Body:       `{"status":"RESOURCE_EXHAUSTED","reason":"QUOTA_EXHAUSTED","retryDelay":"5h"}`,
		},
	}
}

func repeatUsage(guard *guard, record pluginapi.UsageRecord, count int) {
	for range count {
		guard.handleUsage(record)
	}
}

func assertRuntimeFieldClear(t *testing.T, request runtimeOverrideRequest, field string, revision uint64) {
	t.Helper()
	if len(request.Clear) != 1 || request.Clear[0] != field {
		t.Fatalf("%s clear request = %#v", field, request)
	}
	if request.IfRevision == nil || *request.IfRevision != revision || request.IfRevisionField != field {
		t.Fatalf("%s clear CAS request = %#v", field, request)
	}
}
