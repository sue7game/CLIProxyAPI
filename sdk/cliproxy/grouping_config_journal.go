package cliproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

type groupingSourceIntent struct {
	Schema       int               `json:"schema"`
	SourcePath   string            `json:"source_path"`
	SourceKind   string            `json:"source_kind"`
	BeforeExists bool              `json:"before_exists"`
	AfterExists  bool              `json:"after_exists"`
	PendingIDs   []string          `json:"pending_ids,omitempty"`
	Revision     uint64            `json:"revision"`
	Before       grouping.Snapshot `json:"before"`
	After        grouping.Snapshot `json:"after"`
	BeforeHash   string            `json:"before_hash"`
	AfterHash    string            `json:"after_hash"`
	Signature    string            `json:"signature"`
}

// commitSourceTransaction requires g.mu and never publishes source bytes in its journal.
func (g *groupingService) commitSourceTransaction(change groupingFileChange, before, after grouping.Snapshot) (grouping.Snapshot, error) {
	intent, staged, err := g.prepareSourceIntent(change, before, after)
	if err != nil {
		return grouping.Snapshot{}, err
	}
	result, err := g.publishSourcePolicy(before.Revision, staged)
	if err == nil {
		change.path = intent.SourcePath
		err = g.writeIntentSource(intent, change)
	}
	if err == nil {
		result, err = g.publishSourcePolicy(result.Revision, intent.After)
	}
	if err == nil {
		err = g.finishSourceIntent()
	}
	if err != nil {
		return grouping.Snapshot{}, g.failSourceTransaction()
	}
	return result, nil
}

func (g *groupingService) prepareSourceIntent(change groupingFileChange, before, after grouping.Snapshot) (groupingSourceIntent, grouping.Snapshot, error) {
	var empty groupingSourceIntent
	if err := g.validateSourceBase(change, before, after); err != nil {
		return empty, grouping.Snapshot{}, err
	}
	path, kind, err := g.canonicalSourcePath(change.path)
	if err != nil {
		return empty, grouping.Snapshot{}, err
	}
	pendingIDs, err := g.sourceIntentCredentialIDs(path, kind, change.after)
	if err != nil {
		return empty, grouping.Snapshot{}, err
	}
	intent := groupingSourceIntent{Schema: 2, SourcePath: path, SourceKind: kind,
		BeforeExists: change.before != nil, AfterExists: true, PendingIDs: append([]string(nil), pendingIDs...),
		Revision: before.Revision, Before: before.Clone(), After: sourceSnapshotAt(after, before.Revision+2),
		BeforeHash: sourceStateHash(change.before), AfterHash: sourceStateHash(change.after)}
	if !validSourceIntent(intent) {
		return empty, grouping.Snapshot{}, grouping.ErrInvalid
	}
	staged, err := stageSourceIntent(intent)
	if err != nil {
		return empty, grouping.Snapshot{}, err
	}
	intent.Signature, err = g.sourceIntentSignature(intent)
	if err != nil {
		return empty, grouping.Snapshot{}, err
	}
	if err := g.writeSourceIntent(intent); err != nil {
		return empty, grouping.Snapshot{}, err
	}
	return intent, staged, nil
}

func (g *groupingService) validateSourceBase(change groupingFileChange, before, after grouping.Snapshot) error {
	if g == nil || g.owner == nil || g.store == nil || change.after == nil {
		return grouping.ErrInvalid
	}
	path, kind, err := g.canonicalSourcePath(change.path)
	if err != nil || (kind == "config" && change.before == nil) {
		return grouping.ErrInvalid
	}
	if err := g.sourceTransactionIdle(); err != nil {
		return err
	}
	current, err := g.store.Snapshot()
	if err != nil {
		return grouping.ErrUnavailable
	}
	if !reflect.DeepEqual(current, before) {
		return grouping.ErrRevision
	}
	if before.Revision > math.MaxUint64-3 || before.Namespace != after.Namespace ||
		before.SchemaVersion != after.SchemaVersion || before.Revision != after.Revision ||
		!validSourceSnapshot(before) || !validSourceSnapshot(after) {
		return grouping.ErrInvalid
	}
	data, exists, err := readOptionalSourceFile(path)
	if err != nil || exists != (change.before != nil) || !bytes.Equal(data, change.before) {
		return grouping.ErrConflict
	}
	return g.store.CheckIntegrity()
}

func (g *groupingService) sourceTransactionIdle() error {
	if g.sourcePending {
		return grouping.ErrConflict
	}
	if _, err := os.Lstat(filepath.Join(g.path, "activation.pending")); !errors.Is(err, os.ErrNotExist) {
		return grouping.ErrConflict
	}
	path := filepath.Join(g.path, "config.pending")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	intent, err := g.readSourceIntent(path)
	if err != nil {
		return g.failSourceTransaction()
	}
	current, err := g.store.Snapshot()
	if err != nil || !sourceRecoveryStateAllowed(current, intent) {
		return g.failSourceTransaction()
	}
	return grouping.ErrConflict
}

func stageSourcePolicy(before, after grouping.Snapshot) (grouping.Snapshot, error) {
	staged := before.Clone()
	for id, group := range after.Groups {
		if _, exists := staged.Groups[id]; !exists {
			staged.Groups[id] = group
		}
	}
	for id, old := range before.Identities {
		if next, exists := after.Identities[id]; !exists || next != old {
			old.State = grouping.PendingRebind
			staged.Identities[id] = old
		}
	}
	for id, next := range after.Identities {
		if _, exists := before.Identities[id]; !exists {
			next.State = grouping.PendingRebind
			staged.Identities[id] = next
		}
	}
	staged = sourceSnapshotAt(staged, before.Revision+1)
	return staged, staged.Validate()
}

func sourceSnapshotAt(snapshot grouping.Snapshot, revision uint64) grouping.Snapshot {
	snapshot = snapshot.Clone()
	snapshot.Revision, snapshot.Digest = revision, ""
	data, _ := json.Marshal(snapshot) // Snapshot contains only JSON-native validated values.
	digest := sha256.Sum256(data)
	snapshot.Digest = hex.EncodeToString(digest[:])
	return snapshot
}

func sameSourcePolicy(left, right grouping.Snapshot) bool {
	left.Revision, left.Digest, right.Revision, right.Digest = 0, "", 0, ""
	return reflect.DeepEqual(left, right)
}

func validSourceSnapshot(snapshot grouping.Snapshot) bool {
	if snapshot.Validate() != nil {
		return false
	}
	for _, identity := range snapshot.Identities {
		if !sourceDigestValid(identity.Fingerprint) {
			return false
		}
	}
	return true
}

func sourceDigestValid(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func (g *groupingService) sourceIntentSignature(intent groupingSourceIntent) (string, error) {
	intent.Signature = ""
	data, err := json.Marshal(intent)
	if err != nil {
		return "", grouping.ErrInvalid
	}
	return g.store.Fingerprint("config-intent", string(data))
}

func (g *groupingService) writeSourceIntent(intent groupingSourceIntent) error {
	data, err := json.Marshal(intent)
	if err != nil || len(data) > 128<<20 {
		return grouping.ErrInvalid
	}
	change := groupingFileChange{path: filepath.Join(g.path, "config.pending"), after: data}
	if err := createGroupingSource(change); err != nil {
		return g.failSourceTransaction()
	}
	g.sourcePending = true
	return nil
}

func (g *groupingService) publishSourcePolicy(revision uint64, desired grouping.Snapshot) (grouping.Snapshot, error) {
	return g.store.Update(revision, func(current *grouping.Snapshot) error {
		copy := desired.Clone()
		current.Groups, current.Identities = copy.Groups, copy.Identities
		return nil
	})
}

func (g *groupingService) finishSourceIntent() error {
	if err := removeGroupingFile(filepath.Join(g.path, "config.pending")); err != nil {
		return grouping.ErrUnavailable
	}
	g.sourcePending = false
	return nil
}

func (g *groupingService) failSourceTransaction() error {
	g.unavailable.Store(true)
	if err := g.store.Close(); err != nil {
		return grouping.ErrUnavailable
	}
	return grouping.ErrUnavailable
}
