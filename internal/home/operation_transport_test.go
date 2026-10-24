package home

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClusterLatencyProbeCancellationInterruptsBlockedTCPRead(t *testing.T) {
	for _, stage := range []string{"warmup", "measurement"} {
		t.Run(stage, func(t *testing.T) {
			blocked, release := make(chan struct{}), make(chan struct{})
			var blockedOnce atomic.Bool
			t.Cleanup(func() { close(release) })
			client, _ := newRedisCommandTestClient(t, func(args []string) string {
				measurement := len(args) == 2
				if strings.EqualFold(args[0], "PING") && measurement == (stage == "measurement") && blockedOnce.CompareAndSwap(false, true) {
					close(blocked)
					<-release
				}
				return balanceTestRedisReply(args)
			})
			commandPool := client.cmd
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			done := make(chan error, 1)
			go func() {
				_, errProbe := client.probeClusterLatency(ctx, clusterNodeAddress(clusterNode{IP: client.homeCfg.Host, Port: client.homeCfg.Port}))
				done <- errProbe
			}()
			select {
			case <-blocked:
			case errProbe := <-done:
				t.Fatalf("probe ended before blocked %s: %v", stage, errProbe)
			case <-time.After(2 * time.Second):
				t.Fatalf("probe did not reach %s", stage)
			}
			cancel()
			select {
			case errProbe := <-done:
				if errProbe == nil {
					t.Fatal("canceled probe succeeded")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("canceled probe did not interrupt its blocked TCP read")
			}
			if client.cmd != commandPool {
				t.Fatal("probe cancellation replaced the dispatch command pool")
			}
			if errPing := commandPool.Ping(context.Background()).Err(); errPing != nil {
				t.Fatalf("probe cancellation interrupted the dispatch command pool: %v", errPing)
			}
		})
	}
}
