package groupingadmin

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/groupingapi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/grouping"
)

func modelFixture(t *testing.T) (*fixture, map[string][]string) {
	t.Helper()
	f := newFixture(t, sourceRecord{"tA", grouping.Token, "A", grouping.Active},
		sourceRecord{"tB", grouping.Token, "B", grouping.Active},
		sourceRecord{"tAll", grouping.Token, "all", grouping.Active},
		sourceRecord{"tPending", grouping.Token, "A", grouping.PendingRebind},
		sourceRecord{"cA1", grouping.Credential, "A", grouping.Active},
		sourceRecord{"cA2", grouping.Credential, "A", grouping.Active},
		sourceRecord{"cB", grouping.Credential, "B", grouping.Active},
		sourceRecord{"cAll", grouping.Credential, "all", grouping.Active},
		sourceRecord{"cPending", grouping.Credential, "A", grouping.PendingRebind},
		sourceRecord{"cRetired", grouping.Credential, "B", grouping.Tombstone})
	catalog := map[string][]string{
		f.ids["cA1"]: {"shared", "alpha", "shared"}, f.ids["cA2"]: {"shared", "alias/common"},
		f.ids["cB"]: {"prefix/model", "beta", "shared"}, f.ids["cAll"]: {"shared", "global"},
		f.ids["cPending"]: {"pending-only"}, f.ids["cRetired"]: {"retired-only"},
		f.ids["tA"]: {"token-is-not-credential"}, uuid.NewString(): {"unregistered-only"},
	}
	return f, catalog
}

func TestModelPreviewReusesOriginalCatalogUnderSharedLock(t *testing.T) {
	f, catalog := modelFixture(t)
	before, data := snapshotOf(t, f), policyBytes(t, f)
	calls := 0
	f.backend.options.ModelCatalog = func(ctx context.Context, policy grouping.Snapshot) (map[string][]string, error) {
		calls++
		if ctx == nil || !reflect.DeepEqual(policy, before) {
			t.Error("catalog did not receive the original policy")
		}
		if f.mutex.TryLock() {
			f.mutex.Unlock()
			t.Error("catalog callback ran outside the shared lock")
		}
		clear(policy.Identities)
		return catalog, nil
	}
	result, err := f.backend.Preview(testContext(), groupingapi.BindingRequest{
		CredentialIDs: []string{f.ids["cA1"]}, GroupID: f.groups["B"],
	})
	if err != nil || calls != 1 || !result.ModelsAvailable || result.ModelsScope != groupingapi.RegisteredModelCatalogScope || result.ModelsUnavailableReason != "" {
		t.Fatalf("model preview failed: %+v calls=%d err=%v", result, calls, err)
	}
	want := []groupingapi.ModelAccessChange{
		{TokenID: f.ids["tA"], Before: []string{"alias/common", "alpha", "global", "shared"},
			After: []string{"alias/common", "global", "shared"}, Added: []string{}, Removed: []string{"alpha"}},
		{TokenID: f.ids["tB"], Before: []string{"beta", "global", "prefix/model", "shared"},
			After: []string{"alpha", "beta", "global", "prefix/model", "shared"}, Added: []string{"alpha"}, Removed: []string{}},
	}
	sort.Slice(want, func(i, j int) bool { return want[i].TokenID < want[j].TokenID })
	if !reflect.DeepEqual(result.ModelAccessChanges, want) || len(result.CredentialAccessChanges) != 2 || !result.PermissionExpansion {
		t.Fatalf("incorrect model unions: %+v", result)
	}
	assertUnchanged(t, f, before, data)
}

func TestUnavailableModelsRetainCredentialPreview(t *testing.T) {
	tests := []struct {
		name     string
		callback func(context.Context, grouping.Snapshot) (map[string][]string, error)
		reason   string
	}{
		{"not configured", nil, "not_configured"},
		{"callback error", func(context.Context, grouping.Snapshot) (map[string][]string, error) {
			return map[string][]string{}, errors.New("private-secret registry failure")
		}, "catalog_unavailable"},
		{"nil catalog", func(context.Context, grouping.Snapshot) (map[string][]string, error) {
			return nil, nil
		}, "catalog_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, _ := modelFixture(t)
			f.backend.options.ModelCatalog = test.callback
			result, err := f.backend.Preview(testContext(), groupingapi.BindingRequest{
				CredentialIDs: []string{f.ids["cA1"]}, GroupID: f.groups["B"],
			})
			if err != nil || result.ModelsAvailable || result.ModelAccessChanges != nil || result.ModelsUnavailableReason != test.reason {
				t.Fatalf("unavailable catalog invented a model preview: %+v %v", result, err)
			}
			if !result.PermissionExpansion || len(result.CredentialAccessChanges) != 2 || result.AffectedCount != 1 {
				t.Fatal("model unavailability lost the credential preview")
			}
			data, err := json.Marshal(result)
			if err != nil || strings.Contains(string(data), "private-secret") || !strings.Contains(string(data), `"model_access_changes":null`) {
				t.Fatalf("unsafe unavailable response: %s %v", data, err)
			}
		})
	}
}

func TestInvalidPublicModelIDsMarkCatalogUnavailable(t *testing.T) {
	for _, invalid := range []string{"", " padded", "padded ", "line\nbreak", "zero\x00byte", "\xff"} {
		f, catalog := modelFixture(t)
		catalog[f.ids["cA1"]] = []string{invalid}
		f.backend.options.ModelCatalog = func(context.Context, grouping.Snapshot) (map[string][]string, error) { return catalog, nil }
		result, err := f.backend.Preview(testContext(), groupingapi.BindingRequest{
			CredentialIDs: []string{f.ids["cA1"]}, GroupID: f.groups["B"],
		})
		if err != nil || result.ModelsAvailable || result.ModelsUnavailableReason != "catalog_unavailable" || result.ModelAccessChanges != nil {
			t.Fatalf("invalid public model ID was accepted: %+v %v", result, err)
		}
	}
}

func TestAuthoritativeEmptyModelCatalogDoesNotSuppressConsent(t *testing.T) {
	f, _ := modelFixture(t)
	f.backend.options.ModelCatalog = func(context.Context, grouping.Snapshot) (map[string][]string, error) {
		return map[string][]string{}, nil
	}
	result, err := f.backend.Preview(testContext(), groupingapi.BindingRequest{
		CredentialIDs: []string{f.ids["cA1"]}, GroupID: "all",
	})
	if err != nil || !result.ModelsAvailable || result.ModelAccessChanges == nil || len(result.ModelAccessChanges) != 0 || !result.PermissionExpansion {
		t.Fatalf("empty model catalog confused with unavailable or suppressed consent: %+v %v", result, err)
	}
}

func TestInvalidPreviewDoesNotReadModelCatalog(t *testing.T) {
	f, _ := modelFixture(t)
	f.backend.options.ModelCatalog = func(context.Context, grouping.Snapshot) (map[string][]string, error) {
		t.Error("invalid preview reached model catalog")
		return map[string][]string{}, nil
	}
	_, err := f.backend.Preview(testContext(), groupingapi.BindingRequest{TokenIDs: []string{f.ids["cA1"]}, GroupID: "all"})
	if !errors.Is(err, groupingapi.ErrConflict) {
		t.Fatal("invalid preview did not fail closed")
	}
}
