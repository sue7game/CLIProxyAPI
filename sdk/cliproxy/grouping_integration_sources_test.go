package cliproxy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/grouping"
)

func TestGroupingInitializationDoesNotModifySourcesForExistingInstallation(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	before, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.service.grouping.path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.backend.Initialize(f.ctx); err == nil {
		t.Fatal("existing installation was overwritten")
	}
	after, err := os.ReadFile(f.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed preflight changed configuration")
	}
}

func TestGroupingInitializationRetriesPartialUUIDWrites(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	_, change, err := prepareGroupingConfig(f.path, f.service.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeGroupingSource(*change); err != nil {
		t.Fatal(err)
	}
	changes, err := prepareGroupingFileIDs(f.authDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeGroupingSource(changes[0]); err != nil {
		t.Fatal(err)
	}
	if err := f.restart(t); err != nil {
		t.Fatal(err)
	}
	f.initialize(t)
	assertGroupingIntegrationSourceIDs(t, f)
	data, err := os.ReadFile(changes[0].path)
	if err != nil || !bytes.Equal(data, changes[0].after) {
		t.Fatal("retry replaced a persisted source UUID")
	}
}

func TestGroupingMissingPolicyCannotBeReinitialized(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	f.initialize(t)
	g := f.service.grouping
	if err := g.close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(g.path, g.path+".backup"); err != nil {
		t.Fatal(err)
	}
	if err := f.start(t); err != nil {
		t.Fatal(err)
	}
	status, err := f.backend.Status(f.ctx)
	if err != nil || !status.Initialized || status.Healthy {
		t.Fatal("missing installation is not visible as unhealthy")
	}
	if _, err := f.backend.Initialize(f.ctx); err == nil {
		t.Fatal("missing policy reset existing bindings")
	}
}

func TestGroupingManagedConfigDoesNotApproveExternalFileChanges(t *testing.T) {
	for _, kind := range []string{"replacement", "addition"} {
		t.Run(kind, func(t *testing.T) {
			f := newGroupingIntegrationFixture(t)
			f.initialize(t)
			path := filepath.Join(f.authDir, "account-a.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var metadata map[string]any
			if err := json.Unmarshal(data, &metadata); err != nil {
				t.Fatal(err)
			}
			id := metadata["grouping_id"].(string)
			if kind == "addition" {
				path = filepath.Join(f.authDir, "external.json")
				id = "11111111-1111-4111-8111-111111111111"
				metadata["grouping_id"] = id
			}
			metadata["account_id"] = "externally-replaced-account"
			data, err = json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			cfg := f.service.cfg.CloneForRuntime()
			proposed := cfg.CloneForRuntime()
			proposed.Debug = !cfg.Debug
			err = f.service.applyGroupingConfigMutation(f.ctx, management.ConfigApplyRequest{Current: cfg, Proposed: proposed, Operation: "debug"})
			if err != nil {
				t.Fatal(err)
			}
			if f.snapshot(t).Identities[id].State != grouping.PendingRebind {
				t.Fatal("unrelated configuration edit approved an external credential")
			}
		})
	}
}

func TestGroupingManagedRotationRetainsLogicalTokenAndGroup(t *testing.T) {
	f := newGroupingIntegrationFixture(t)
	f.initialize(t)
	group := f.createGroup(t, "Restricted")
	var id string
	for _, identity := range f.snapshot(t).Identities {
		if identity.Kind == grouping.Token {
			id = identity.ID
		}
	}
	f.bind(t, groupingapi.BindingRequest{TokenIDs: []string{id}, GroupID: group})
	before := f.service.cfg.CloneForRuntime()
	proposed := before.CloneForRuntime()
	proposed.APIKeys[0] = "rotated-integration-token-only"
	request := management.ConfigApplyRequest{Current: before, Proposed: proposed, Operation: "api-keys"}
	if err := f.service.applyGroupingConfigMutation(f.ctx, request); err == nil {
		t.Fatal("ambiguous bulk rotation reset a token identity")
	}
	request.TokenRotation = &management.APIKeyRotation{Old: before.APIKeys[0], New: proposed.APIKeys[0]}
	if err := f.service.applyGroupingConfigMutation(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	identity := f.snapshot(t).Identities[id]
	if identity.GroupID != group || identity.State != grouping.Active {
		t.Fatal("rotation lost the logical token or group")
	}
}
