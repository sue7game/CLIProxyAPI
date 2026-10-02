package cliproxy

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

// groupingOAuthStorage limits a prepared OAuth save to its signed bytes and path.
// Rendering the provider storage once avoids nondeterministic second serializations.
type groupingOAuthStorage struct {
	g            *groupingService
	change       groupingFileChange
	intent       groupingSourceIntent
	metadataHash string
	mu           sync.Mutex
	invalid      bool
	written      bool
}

func newGroupingOAuthStorage(g *groupingService, change groupingFileChange, intent groupingSourceIntent, metadata map[string]any) (*groupingOAuthStorage, error) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, grouping.ErrInvalid
	}
	return &groupingOAuthStorage{g: g, change: change, intent: intent, metadataHash: groupingSourceDigest(raw)}, nil
}

// SetMetadata accepts only the metadata already included in the signed transaction.
func (s *groupingOAuthStorage) SetMetadata(metadata map[string]any) {
	raw, err := json.Marshal(metadata)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || groupingSourceDigest(raw) != s.metadataHash {
		s.invalid = true
	}
}

// SaveTokenToFile persists one prepared source exclusively or replaces its exact predecessor.
func (s *groupingOAuthStorage) SaveTokenToFile(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.g
	defer g.notify()
	g.transactionMu.Lock()
	defer g.transactionMu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.unavailable.Load() || s.invalid {
		return g.failSourceTransaction()
	}
	canonical, kind, err := g.canonicalSourcePath(path)
	if err != nil || kind != "auth" || canonical != s.intent.SourcePath {
		return g.failSourceTransaction()
	}
	intent, err := g.readSourceIntent(filepath.Join(g.path, "config.pending"))
	if err != nil || intent.Signature != s.intent.Signature {
		return g.failSourceTransaction()
	}
	current, err := g.store.Snapshot()
	staged, stageErr := stageSourceIntent(intent)
	if err != nil || stageErr != nil || !reflect.DeepEqual(current, staged) {
		return g.failSourceTransaction()
	}
	if s.written {
		raw, err := readSourceTransactionFile(canonical, 64<<20)
		if err != nil || groupingSourceDigest(raw) != intent.AfterHash {
			return g.failSourceTransaction()
		}
		return nil
	}
	if err := g.writeIntentSource(intent, s.change); err != nil {
		return g.failSourceTransaction()
	}
	s.written = true
	return nil
}
