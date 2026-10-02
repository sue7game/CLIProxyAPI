package cliproxy

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

// recoverSourceTransaction requires g.mu and only accepts signed, identifiable states.
func (g *groupingService) recoverSourceTransaction() error {
	path := filepath.Join(g.path, "config.pending")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	intent, err := g.readSourceIntent(path)
	if err != nil {
		return g.failSourceTransaction()
	}
	if err := g.recoverSourcePolicy(intent); err != nil {
		return g.failSourceTransaction()
	}
	if err := g.finishSourceIntent(); err != nil {
		return g.failSourceTransaction()
	}
	return nil
}

func (g *groupingService) readSourceIntent(path string) (groupingSourceIntent, error) {
	var intent groupingSourceIntent
	if _, err := os.Lstat(filepath.Join(g.path, "activation.pending")); !errors.Is(err, os.ErrNotExist) {
		return intent, grouping.ErrConflict
	}
	data, err := readSourceTransactionFile(path, 128<<20)
	if err != nil {
		return intent, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&intent) != nil || decoder.Decode(new(any)) != io.EOF || !validSourceIntent(intent) {
		return intent, grouping.ErrInvalid
	}
	signature, err := g.sourceIntentSignature(intent)
	if err != nil || !hmac.Equal([]byte(signature), []byte(intent.Signature)) {
		return intent, grouping.ErrInvalid
	}
	if err := g.validateIntentSource(intent); err != nil {
		return intent, err
	}
	return intent, nil
}

func validSourceIntent(intent groupingSourceIntent) bool {
	if intent.Schema != 2 || intent.Revision == 0 || intent.Revision > math.MaxUint64-3 ||
		intent.Before.Revision != intent.Revision || intent.After.Revision != intent.Revision+2 ||
		intent.Before.Namespace != intent.After.Namespace || !validSourceSnapshot(intent.Before) || !validSourceSnapshot(intent.After) {
		return false
	}
	if !filepath.IsAbs(intent.SourcePath) || filepath.Clean(intent.SourcePath) != intent.SourcePath ||
		!intent.AfterExists || !sourceDigestValid(intent.AfterHash) ||
		(intent.BeforeExists && !sourceDigestValid(intent.BeforeHash)) || (!intent.BeforeExists && intent.BeforeHash != "") {
		return false
	}
	if intent.SourceKind != "config" && intent.SourceKind != "auth" ||
		intent.SourceKind == "config" && (!intent.BeforeExists || len(intent.PendingIDs) != 0) ||
		intent.SourceKind == "auth" && len(intent.PendingIDs) == 0 {
		return false
	}
	if _, err := stageSourceIntent(intent); err != nil {
		return false
	}
	return reflect.DeepEqual(intent.Before, sourceSnapshotAt(intent.Before, intent.Before.Revision)) &&
		reflect.DeepEqual(intent.After, sourceSnapshotAt(intent.After, intent.After.Revision))
}

func stageSourceIntent(intent groupingSourceIntent) (grouping.Snapshot, error) {
	staged, err := stageSourcePolicy(intent.Before, intent.After)
	if err != nil {
		return grouping.Snapshot{}, err
	}
	seen := make(map[string]bool, len(intent.PendingIDs))
	for _, id := range intent.PendingIDs {
		identity, ok := staged.Identities[id]
		if !ok || identity.Kind != grouping.Credential || seen[id] || identity.State == grouping.Tombstone {
			return grouping.Snapshot{}, grouping.ErrInvalid
		}
		seen[id] = true
		identity.State = grouping.PendingRebind
		staged.Identities[id] = identity
	}
	staged = sourceSnapshotAt(staged, staged.Revision)
	return staged, staged.Validate()
}

func (g *groupingService) recoverSourcePolicy(intent groupingSourceIntent) error {
	if err := g.store.CheckIntegrity(); err != nil {
		return err
	}
	if err := g.validateIntentSource(intent); err != nil {
		return err
	}
	current, err := g.store.Snapshot()
	if err != nil || !sourceRecoveryStateAllowed(current, intent) {
		return grouping.ErrUnavailable
	}
	data, exists, err := readOptionalSourceFile(intent.SourcePath)
	if err != nil {
		return err
	}
	want := intent.Before
	if exists == intent.AfterExists && sourceStateHash(data) == intent.AfterHash {
		want = intent.After
	} else if exists != intent.BeforeExists || sourceStateHash(data) != intent.BeforeHash {
		return grouping.ErrUnavailable
	}
	// A durable terminal policy cannot be undone by replaying old source bytes.
	staged, err := stageSourceIntent(intent)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, intent.Before) && !reflect.DeepEqual(current, staged) && !sameSourcePolicy(current, want) {
		return grouping.ErrUnavailable
	}
	if !sameSourcePolicy(current, want) {
		_, err = g.publishSourcePolicy(current.Revision, want)
	}
	return err
}

func sourceRecoveryStateAllowed(current grouping.Snapshot, intent groupingSourceIntent) bool {
	staged, err := stageSourceIntent(intent)
	if err != nil {
		return false
	}
	if reflect.DeepEqual(current, intent.Before) || reflect.DeepEqual(current, staged) {
		return true
	}
	// Recovery may commit before journal removal; accept only that durable result.
	for _, revision := range []uint64{intent.Revision + 1, intent.Revision + 2, intent.Revision + 3} {
		if reflect.DeepEqual(current, sourceSnapshotAt(intent.After, revision)) ||
			(revision > intent.Revision+1 && reflect.DeepEqual(current, sourceSnapshotAt(intent.Before, revision))) {
			return true
		}
	}
	return false
}
