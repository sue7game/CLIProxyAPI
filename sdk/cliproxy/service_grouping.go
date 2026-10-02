package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/groupingadmin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	log "github.com/sirupsen/logrus"
)

type groupingService struct {
	context            context.Context
	mu                 sync.Mutex
	transactionMu      sync.Mutex
	owner              *Service
	store              *grouping.Store
	path               string
	enabled            atomic.Bool
	current            atomic.Pointer[config.Config]
	unavailable        atomic.Bool
	sourcesUnavailable atomic.Bool
	closed             bool
	installed          bool
	sourcePending      bool
	deferredConfig     *groupingDeferredConfig
	catalog            map[string]groupingadmin.Label
	monitorCancel      context.CancelFunc
	monitorDone        chan struct{}
}

func groupingStorePath(configPath string, cfg *config.Config) string {
	path := strings.TrimSpace(cfg.Grouping.StorePath)
	if path == "" {
		path = "grouping-policy"
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(configPath), path)
	}
	return filepath.Clean(path)
}

func (s *Service) prepareGrouping(ctx context.Context) error {
	if err := config.ValidateGroupingMode(s.cfg); err != nil {
		return err
	}
	g := &groupingService{owner: s, path: groupingStorePath(s.configPath, s.cfg), context: ctx}
	g.current.Store(s.cfg.CloneForRuntime())
	s.grouping = g
	if s.cfg.Home.Enabled {
		return nil
	}
	g.installed = g.hasInstallationReceipt()
	if _, err := os.Lstat(g.path); errors.Is(err, os.ErrNotExist) && !s.cfg.Grouping.Enabled {
		return nil
	}
	store, err := grouping.OpenStore(g.path)
	if err != nil {
		if s.cfg.Grouping.Enabled {
			return fmt.Errorf("grouping: existing policy cannot be opened; refusing enabled startup")
		}
		log.Warn("grouping policy is unavailable; initialization cannot overwrite existing data")
		return nil
	}
	g.store = store
	if err := g.ensureInstallationReceipt(store); err != nil {
		return err
	}
	g.installed = true
	if err := g.recoverActivationIntent(); err != nil {
		return err
	}
	if err := g.recoverSourceTransaction(); err != nil {
		return err
	}
	if s.cfg.Grouping.Enabled {
		if err := g.validateLocalConfig(s.cfg); err != nil {
			return err
		}
		g.enabled.Store(true)
		g.installPolicy()
		if err := g.reconcileSources(ctx, s.cfg); err != nil {
			return err
		}
	} else if auths, err := g.collectSources(s.cfg, nil); err == nil {
		g.refreshCatalog(s.cfg, auths)
	}
	g.startMonitor(ctx)
	return nil
}

func (g *groupingService) validateLocalConfig(cfg *config.Config) error {
	if err := config.ValidateGroupingMode(cfg); err != nil {
		return err
	}
	if cfg.Home.Enabled {
		return fmt.Errorf("grouping: local administration is unavailable in Home mode")
	}
	if _, ok := sdkauth.GetTokenStore().(*sdkauth.FileTokenStore); !ok {
		return fmt.Errorf("grouping: remote credential storage is not supported by local policy persistence")
	}
	if len(cfg.APIKeys) == 0 {
		return fmt.Errorf("grouping: configure at least one authenticated API key before activation")
	}
	if cfg.Grouping.Enabled {
		return config.ValidateGroupingCredentialIDs(cfg)
	}
	return nil
}

func (g *groupingService) principalCurrent(principal sdkaccess.AuthenticatedPrincipal) bool {
	cfg := g.current.Load()
	if cfg == nil || principal.Provider != sdkaccess.DefaultAccessProviderName {
		return false
	}
	for _, key := range cfg.APIKeys {
		if strings.TrimSpace(key) == principal.Subject {
			return true
		}
	}
	return false
}

func (g *groupingService) installPolicy() {
	if g.owner.coreManager != nil {
		g.owner.coreManager.SetCredentialAccessPolicy(&groupingAccessPolicy{store: g.store, principalCurrent: g.principalCurrent, ready: g.healthy})
	}
}

func (g *groupingService) healthy() bool {
	return !g.unavailable.Load() && !g.sourcesUnavailable.Load()
}

func (g *groupingService) notify() {
	if g.owner.coreManager != nil {
		g.owner.coreManager.NotifyCredentialAccessChanged()
	}
}

func (g *groupingService) startMonitor(parent context.Context) {
	if g.monitorCancel != nil || g.store == nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	g.monitorCancel, g.monitorDone = cancel, make(chan struct{})
	store, done := g.store, g.monitorDone
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := store.CheckIntegrity(); err != nil {
					g.unavailable.Store(true)
					log.Error("grouping policy storage integrity check failed; authorization is unavailable")
					g.notify()
					return
				}
			}
		}
	}()
}

func (g *groupingService) close() error {
	if g == nil {
		return nil
	}
	g.transactionMu.Lock()
	defer g.transactionMu.Unlock()
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	g.unavailable.Store(true)
	cancel, done, store := g.monitorCancel, g.monitorDone, g.store
	g.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	g.notify()
	return store.Close()
}
