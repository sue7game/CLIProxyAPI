package cliproxy

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"gopkg.in/yaml.v3"
)

const groupingSourceGuardExternalToken = "external-downstream-fixture"

func TestGroupingManagedTransitionRejectsUnreconciledPolicyBase(t *testing.T) {
	for _, change := range []string{"credential", "token"} {
		t.Run(change, func(t *testing.T) {
			f := newGroupingIntegrationFixture(t)
			f.initialize(t)
			before := f.snapshot(t)
			cfg := f.service.cfg.CloneForRuntime()
			if change == "credential" {
				cfg.CodexKey[0].APIKey = "unreconciled-key-fixture"
			} else {
				cfg.APIKeys = append(cfg.APIKeys, groupingSourceGuardExternalToken)
			}
			// Simulate a runtime snapshot published without source reconciliation.
			f.service.grouping.current.Store(cfg)
			proposed := cfg.CloneForRuntime()
			proposed.Debug = true
			_, err := f.service.grouping.managedPolicyTransition(before, proposed, nil)
			var conflict *management.ConfigApplyError
			if !errors.As(err, &conflict) || conflict.StatusCode != http.StatusConflict || conflict.Code != "grouping_source_changed" {
				t.Fatalf("unreconciled policy base was accepted: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("policy-base validation modified signed state")
			}
		})
	}
}

func TestGroupingManagedTypedMutationRejectsUnacceptedSources(t *testing.T) {
	for _, change := range []string{"credential", "token"} {
		t.Run(change, func(t *testing.T) {
			f := newGroupingIntegrationFixture(t)
			f.initialize(t)
			before := f.snapshot(t)
			external := mutateGroupingSourceGuardDocument(t, readGroupingSourceGuardFile(t, f.path), change)
			writeGroupingSourceGuardFile(t, f.path, external)
			current := f.service.cfg.CloneForRuntime()
			proposed := current.CloneForRuntime()
			proposed.Debug = true
			err := f.service.applyGroupingConfigMutation(f.ctx, management.ConfigApplyRequest{Current: current, Proposed: proposed, Operation: "debug"})
			var conflict *management.ConfigApplyError
			if !errors.As(err, &conflict) || conflict.Code != "grouping_source_changed" {
				t.Fatalf("typed mutation accepted unacknowledged sources: %v", err)
			}
			if !reflect.DeepEqual(before, f.snapshot(t)) || !bytes.Equal(external, readGroupingSourceGuardFile(t, f.path)) {
				t.Fatal("rejected typed mutation changed policy or disk source")
			}
		})
	}
}

func newGroupingSourceGuardFixture(t *testing.T, enabled, canonical bool) *groupingHTTPFixture {
	t.Helper()
	f := newGroupingHTTPFixture(t)
	f.managed(t, http.MethodPost, "/grouping/initialize", gin.H{}, 0)
	if enabled {
		f.managed(t, http.MethodPatch, "/grouping/activation", gin.H{"enabled": true}, f.snapshot(t).Revision)
	}
	if canonical {
		f.managed(t, http.MethodPatch, "/config/observability/logs/debug", false, 0)
	}
	return f
}

func assertGroupingSourceGuardHealthy(t *testing.T, f *groupingHTTPFixture) {
	t.Helper()
	status, err := f.backend.Status(f.ctx)
	if err != nil || !status.Healthy || f.service.grouping.unavailable.Load() {
		t.Fatalf("source validation left the accepted runtime unavailable: %v", err)
	}
}

func mutateGroupingSourceGuardDocument(t *testing.T, raw []byte, change string) []byte {
	t.Helper()
	if change == "credential" {
		external := bytes.Replace(raw, []byte("integration-upstream-only"), []byte("external-replacement-fixture"), 1)
		if bytes.Equal(raw, external) {
			t.Fatal("fixture credential was not replaced")
		}
		return external
	}
	if change != "token" {
		t.Fatalf("unknown fixture source change: %s", change)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	root := doc.Content[0]
	keys := groupingDocumentField(root, "api-keys", yaml.SequenceNode, "!!seq")
	if keys.Kind != yaml.SequenceNode {
		access := groupingDocumentField(root, "access", yaml.MappingNode, "!!map")
		keys = groupingDocumentField(access, "api-keys", yaml.SequenceNode, "!!seq")
	}
	if keys.Kind != yaml.SequenceNode || len(keys.Content) != 1 || keys.Content[0].Value != "integration-downstream-only" {
		t.Fatal("fixture downstream token sequence not found")
	}
	keys.Content = append(keys.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: groupingSourceGuardExternalToken})
	external, err := yaml.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	return external
}

func readGroupingSourceGuardFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeGroupingSourceGuardFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
