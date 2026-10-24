package management

import (
	"net/http"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestGroupingActivationWaitsForLegacyWriteBeforePublishing(t *testing.T) {
	h, path, _ := newIssue6631Handler(t, "request-retry: 3\n")
	h.envSecret, h.failedAttempts = "management-secret", make(map[string]*attemptInfo)
	entered, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(unblock)
	router := gin.New()
	router.Use(h.Middleware())
	router.PUT("/v0/management/request-retry", func(c *gin.Context) {
		close(entered)
		<-resume
		h.PutRequestRetry(c)
	})
	legacyDone := make(chan int, 1)
	go func() {
		legacyDone <- legacyGroupingRequest(router, http.MethodPut, "/v0/management/request-retry", `{"value":5}`).Code
	}()
	<-entered
	if h.legacyMutationMu.TryLock() {
		h.legacyMutationMu.Unlock()
		t.Fatal("legacy request did not hold its mutation fence")
	}
	attempted, managedDone := make(chan struct{}), make(chan error, 1)
	go func() {
		close(attempted)
		release := h.BeginConfigMutationFence()
		defer release()
		managedDone <- publishGroupingActivationForTest(h, path)
	}()
	<-attempted
	unblock()
	if status := <-legacyDone; status != http.StatusOK {
		t.Fatalf("legacy write status=%d", status)
	}
	if err := <-managedDone; err != nil {
		t.Fatal(err)
	}
	response := legacyGroupingRequest(router, http.MethodPut, "/v0/management/request-retry", `{"value":7}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("legacy write crossed activation: %d %s", response.Code, response.Body.String())
	}
	disk := readIssue6631Disk(t, path)
	if !disk.Grouping.Enabled || disk.RequestRetry != 5 {
		t.Fatal("activation lost the completed legacy write or a late write overwrote activation")
	}
}

func publishGroupingActivationForTest(h *Handler, path string) error {
	cfg, err := config.LoadConfig(path)
	if err != nil {
		return err
	}
	cfg.Grouping.Enabled = true
	if err = config.SaveConfigPreserveComments(path, cfg); err != nil {
		return err
	}
	published, err := config.LoadConfig(path)
	if err != nil {
		return err
	}
	h.SetConfig(published)
	return nil
}
