package cliproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

type groupingActivationIntent struct {
	Version       int    `json:"version"`
	Revision      uint64 `json:"revision"`
	BeforeEnabled bool   `json:"before_enabled"`
	Enabled       bool   `json:"enabled"`
	BeforeHash    string `json:"before_hash"`
	AfterHash     string `json:"after_hash"`
	Signature     string `json:"signature"`
}

func groupingSourceDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (g *groupingService) activationSignature(intent groupingActivationIntent) (string, error) {
	intent.Signature = ""
	data, err := json.Marshal(intent)
	if err != nil {
		return "", grouping.ErrUnavailable
	}
	return g.store.Fingerprint("activation-intent", string(data))
}

func (g *groupingService) prepareActivationIntent(expected uint64, enabled bool, change groupingFileChange) error {
	if _, err := os.Lstat(filepath.Join(g.path, "config.pending")); !errors.Is(err, os.ErrNotExist) {
		return grouping.ErrUnavailable
	}
	intent := groupingActivationIntent{Version: 1, Revision: expected, BeforeEnabled: g.enabled.Load(), Enabled: enabled, BeforeHash: groupingSourceDigest(change.before), AfterHash: groupingSourceDigest(change.after)}
	signature, err := g.activationSignature(intent)
	if err != nil {
		return err
	}
	intent.Signature = signature
	data, err := json.Marshal(intent)
	if err != nil {
		return grouping.ErrUnavailable
	}
	journal := groupingFileChange{path: filepath.Join(g.path, "activation.pending"), after: data}
	if err := createGroupingSource(journal); err != nil {
		return g.failActivation()
	}
	return nil
}

func (g *groupingService) finishActivationIntent() error {
	if err := removeGroupingFile(filepath.Join(g.path, "activation.pending")); err != nil {
		return fmt.Errorf("grouping: cannot finalize activation transaction")
	}
	return nil
}

// recoverActivationIntent completes or cancels only a fully identifiable write.
// Unknown disk states never reset bindings or silently disable enforcement.
func (g *groupingService) recoverActivationIntent() error {
	path := filepath.Join(g.path, "activation.pending")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return grouping.ErrUnavailable
	}
	if _, err := os.Lstat(filepath.Join(g.path, "config.pending")); !errors.Is(err, os.ErrNotExist) {
		return grouping.ErrUnavailable
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return grouping.ErrUnavailable
	}
	var intent groupingActivationIntent
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil || decoder.Decode(new(any)) != io.EOF {
		return grouping.ErrUnavailable
	}
	if intent.Version != 1 || intent.Revision == 0 || intent.BeforeEnabled == intent.Enabled || len(intent.BeforeHash) != 64 || len(intent.AfterHash) != 64 {
		return grouping.ErrUnavailable
	}
	signature, err := g.activationSignature(intent)
	if err != nil || signature != intent.Signature {
		return grouping.ErrUnavailable
	}
	snapshot, err := g.store.Snapshot()
	if err != nil {
		return err
	}
	configBytes, err := os.ReadFile(g.owner.configPath)
	if err != nil {
		return grouping.ErrUnavailable
	}
	digest := groupingSourceDigest(configBytes)
	cfg := g.current.Load()
	committed := snapshot.Revision == intent.Revision+1 && digest == intent.AfterHash && cfg.Grouping.Enabled == intent.Enabled
	cancelled := (snapshot.Revision == intent.Revision || snapshot.Revision == intent.Revision+1) && digest == intent.BeforeHash && cfg.Grouping.Enabled == intent.BeforeEnabled
	if !committed && !cancelled {
		return fmt.Errorf("grouping: unresolved activation transaction; restore a consistent configuration and policy backup")
	}
	return g.finishActivationIntent()
}
