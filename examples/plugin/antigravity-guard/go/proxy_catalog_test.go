package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestProxyCatalogUsesOpaqueCanonicalIdentity(t *testing.T) {
	catalog := deterministicProxyCatalog()
	first, firstReusable := catalog.describe("SOCKS5://alice:first-secret@Proxy.Example:1080")
	equivalent, equivalentReusable := catalog.describe("socks5://alice:first-secret@proxy.example:1080")
	differentPassword, differentReusable := catalog.describe("socks5://alice:second-secret@proxy.example:1080")
	if !firstReusable || !equivalentReusable || !differentReusable {
		t.Fatal("valid SOCKS5 proxies must be reusable")
	}
	if first.ID == "" || first.ID != equivalent.ID {
		t.Fatalf("canonical proxy IDs differ: %q and %q", first.ID, equivalent.ID)
	}
	if first.ID == differentPassword.ID {
		t.Fatal("proxies with different passwords must not share a proxy ID")
	}
	for _, value := range []string{first.ID, first.Display, equivalent.ID, equivalent.Display} {
		if strings.Contains(value, "first-secret") {
			t.Fatalf("proxy descriptor leaked password: %q", value)
		}
	}
	if _, reusable := catalog.describe("direct"); reusable {
		t.Fatal("forced direct must not receive a proxy ID")
	}
}

func TestProxyCatalogAliasValidationAndLifecycle(t *testing.T) {
	catalog := deterministicProxyCatalog()
	first, _ := catalog.describe("socks5://alice:first@proxy.example:1080")
	second, _ := catalog.describe("socks5://alice:second@proxy.example:1080")
	active := map[string]struct{}{first.ID: {}, second.ID: {}}

	alias, errAlias := catalog.setAlias(first.ID, "  美国住宅 Proxy 01  ", active)
	if errAlias != nil || alias != "美国住宅 Proxy 01" {
		t.Fatalf("setAlias() = %q, %v", alias, errAlias)
	}
	if _, errDuplicate := catalog.setAlias(second.ID, "美国住宅 proxy 01", active); errDuplicate == nil {
		t.Fatal("case-insensitive duplicate alias must be rejected")
	}
	if _, errControl := catalog.setAlias(second.ID, "bad\nalias", active); errControl == nil {
		t.Fatal("control characters must be rejected")
	}
	if _, errLong := catalog.setAlias(second.ID, strings.Repeat("代", proxyAliasMaxRunes+1), active); errLong == nil {
		t.Fatal("aliases over 40 Unicode characters must be rejected")
	}
	if alias, errMax := catalog.setAlias(second.ID, strings.Repeat("代", proxyAliasMaxRunes), active); errMax != nil || alias == "" {
		t.Fatalf("40-character alias rejected: %q, %v", alias, errMax)
	}
	if _, errInactive := catalog.setAlias("p_not-current", "unused", active); errInactive == nil {
		t.Fatal("non-current proxy ID must be rejected")
	}
	if alias, errClear := catalog.setAlias(first.ID, "  ", active); errClear != nil || alias != "" {
		t.Fatalf("clear alias = %q, %v", alias, errClear)
	}
	if catalog.alias(first.ID) != "" {
		t.Fatal("empty alias must clear the stored alias")
	}

	catalog.reconcile(map[string]struct{}{first.ID: {}})
	if catalog.alias(second.ID) != "" {
		t.Fatal("aliases for proxies no longer in use must be removed")
	}
}

func deterministicProxyCatalog() *proxyCatalog {
	return &proxyCatalog{
		key:     bytes.Repeat([]byte{0x5a}, 32),
		aliases: make(map[string]string),
	}
}
