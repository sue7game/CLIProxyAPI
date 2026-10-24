package cliproxy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (g *groupingService) planOAuthRecord(record *coreauth.Auth) (*groupingAuthSourcePlan, *coreauth.Auth, error) {
	path, err := g.oauthRecordPath(record)
	if err != nil {
		return nil, nil, err
	}
	before, _, err := readOptionalSourceFile(path)
	if err != nil {
		return nil, nil, err
	}
	prepared, err := prepareGroupingOAuthMetadata(record, before, path)
	if err != nil {
		return nil, nil, err
	}
	after, err := g.renderOAuthSource(prepared)
	if err != nil {
		return nil, nil, err
	}
	metadata, err := groupingAuthMetadata(after)
	if err != nil || metadata["grouping_id"] != prepared.Metadata["grouping_id"] {
		return nil, nil, grouping.ErrInvalid
	}
	prepared.Metadata = metadata
	plan, err := g.planAuthSource(path, before, after)
	if err != nil {
		return nil, nil, err
	}
	return plan, prepared, nil
}

func prepareGroupingOAuthMetadata(record *coreauth.Auth, before []byte, path string) (*coreauth.Auth, error) {
	prepared := record.Clone()
	if prepared.Metadata == nil {
		prepared.Metadata = make(map[string]any)
	}
	if prepared.Attributes == nil {
		prepared.Attributes = make(map[string]string)
	}
	if id := prepared.Attributes["grouping_id"]; id != "" {
		if other, exists := prepared.Metadata["grouping_id"]; exists && other != id {
			return nil, grouping.ErrConflict
		}
		prepared.Metadata["grouping_id"] = id
	}
	if before != nil {
		old, err := groupingAuthMetadata(before)
		if err != nil {
			return nil, err
		}
		coreauth.MergeExistingAuthMetadata(prepared, old)
	}
	coreauth.NormalizeCredentialMetadata(prepared.Metadata)
	prepared.Metadata["disabled"] = prepared.Disabled
	if _, exists := prepared.Metadata["type"]; !exists {
		prepared.Metadata["type"] = prepared.Provider
	}
	raw, err := json.Marshal(prepared.Metadata)
	if err != nil {
		return nil, grouping.ErrInvalid
	}
	raw, err = assignGroupingAuthFileID(before, raw)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &prepared.Metadata); err != nil {
		return nil, grouping.ErrInvalid
	}
	prepared.Attributes["grouping_id"] = prepared.Metadata["grouping_id"].(string)
	prepared.Attributes[coreauth.AttributePath] = path
	prepared.Attributes[coreauth.AttributeSource] = path
	prepared.Attributes[coreauth.AttributeSourceBackend] = coreauth.AuthSourceFile
	prepared.FileName = filepath.Base(path)
	return prepared, nil
}

func (g *groupingService) renderOAuthSource(record *coreauth.Auth) (raw []byte, err error) {
	if record.Storage == nil {
		data, err := json.Marshal(record.Metadata)
		if err != nil {
			return nil, grouping.ErrInvalid
		}
		return data, nil
	}
	setter, ok := record.Storage.(interface{ SetMetadata(map[string]any) })
	if !ok {
		return nil, grouping.ErrInvalid
	}
	dir, err := os.MkdirTemp(g.path, ".oauth-render-*")
	if err != nil {
		return nil, grouping.ErrUnavailable
	}
	path := filepath.Join(dir, "source.json")
	defer func() {
		// Codex keeps its lockfile after unlocking. This private render directory
		// is never shared with a live credential and can remove that file safely.
		for _, name := range []string{path, path + ".lock"} {
			if fileErr := os.Remove(name); fileErr != nil && !errors.Is(fileErr, os.ErrNotExist) {
				raw, err = nil, grouping.ErrUnavailable
			}
		}
		if dirErr := os.Remove(dir); dirErr != nil {
			raw, err = nil, grouping.ErrUnavailable
		}
	}()
	setter.SetMetadata(record.Metadata)
	if err := record.Storage.SaveTokenToFile(path); err != nil {
		return nil, grouping.ErrUnavailable
	}
	return readSourceTransactionFile(path, 64<<20)
}

func (g *groupingService) validatePersistedOAuthRecord(path string, record *coreauth.Auth, intent *groupingSourceIntent) (*groupingAuthSourcePlan, error) {
	fail := g.failAuthSourceValidation
	if intent != nil {
		fail = g.failSourceTransaction
	}
	raw, err := readSourceTransactionFile(path, 64<<20)
	if err != nil || intent != nil && groupingSourceDigest(raw) != intent.AfterHash {
		return nil, fail()
	}
	cfg, err := g.authSourceConfig()
	if err != nil {
		return nil, fail()
	}
	all, err := g.collectSources(cfg, nil)
	if err != nil {
		return nil, fail()
	}
	target := make([]*coreauth.Auth, 0, 1)
	for _, auth := range all {
		if auth.Attributes[coreauth.AttributePath] == path {
			target = append(target, auth)
		}
	}
	if len(target) != 1 {
		return nil, fail()
	}
	snapshot, err := g.store.Snapshot()
	if intent != nil {
		snapshot = intent.After
	}
	if err != nil || g.validateOAuthIdentity(snapshot, record, target[0]) != nil {
		return nil, fail()
	}
	if err := g.validateAuthSourceBaseline(cfg, snapshot); err != nil {
		return nil, fail()
	}
	return &groupingAuthSourcePlan{cfg: cfg, auths: target}, nil
}

func (g *groupingService) validateOAuthIdentity(snapshot grouping.Snapshot, record, stored *coreauth.Auth) error {
	hash, err := g.store.IdentityHasher()
	if err != nil {
		return err
	}
	identity, err := groupingCredentialIdentity(stored, hash)
	if err != nil || !registeredGroupingSource(snapshot, identity) {
		return grouping.ErrConflict
	}
	expected, err := groupingCredentialIdentity(record, hash)
	if err != nil || expected.ID != identity.ID || expected.Provider != identity.Provider || expected.Fingerprint != identity.Fingerprint {
		return grouping.ErrConflict
	}
	return nil
}
