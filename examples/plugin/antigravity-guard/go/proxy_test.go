package main

import "testing"

func TestValidateProxyURLSupportsForcedDirect(t *testing.T) {
	for _, raw := range []string{"DIRECT", "none"} {
		value, errValidate := validateProxyURL(raw)
		if errValidate != nil || value != "direct" {
			t.Fatalf("raw=%q value=%q error=%v", raw, value, errValidate)
		}
	}
}

func TestValidateProxyURLNormalizesSchemeCase(t *testing.T) {
	value, errValidate := validateProxyURL("SOCKS5://127.0.0.1:1080")
	if errValidate != nil || value != "socks5://127.0.0.1:1080" {
		t.Fatalf("value=%q error=%v", value, errValidate)
	}
}

func TestMaskProxyURLHidesCredentialsAndQuerySecrets(t *testing.T) {
	masked := maskProxyURL("socks5://alice:secret@127.0.0.1:1080?token=token-value#private")
	for _, secret := range []string{"alice", "secret", "token-value", "private"} {
		if masked == "" || containsText(masked, secret) {
			t.Fatalf("masked proxy leaks %q: %q", secret, masked)
		}
	}
	usernameOnly := maskProxyURL("socks5://username-token@127.0.0.1:1080")
	if containsText(usernameOnly, "username-token") {
		t.Fatalf("masked proxy leaks username-only credential: %q", usernameOnly)
	}
	if maskProxyURL("direct") != "强制直连" {
		t.Fatal("forced direct must be distinct from inherited direct")
	}
	if maskProxyURL("not a proxy?token=secret") != "无效代理地址（已隐藏）" {
		t.Fatal("invalid proxy text must not be rendered verbatim")
	}
}

func TestEffectiveProxyUsesHostRuntimeStateAsAuthority(t *testing.T) {
	runtimeProxy := "direct"
	proxy, source := effectiveProxy(hostAuthEntry{
		EffectiveProxyURL: "http://global.example:8080",
		RuntimeOverride:   &runtimeOverride{ProxyURL: &runtimeProxy},
	}, "http://configured.example:8080")
	if proxy != "direct" || source != "runtime_direct" {
		t.Fatalf("effectiveProxy() = %q, %q, want runtime direct", proxy, source)
	}

	proxy, source = effectiveProxy(hostAuthEntry{EffectiveProxyURL: "http://global.example:8080"}, "")
	if proxy != "http://global.example:8080" || source != "global" {
		t.Fatalf("effectiveProxy() = %q, %q, want global proxy", proxy, source)
	}

	proxy, source = effectiveProxy(hostAuthEntry{}, "none")
	if proxy != "direct" || source != "credential" {
		t.Fatalf("effectiveProxy() = %q, %q, want credential direct", proxy, source)
	}
}

func TestReusableProxyRequiresValidConcreteProxy(t *testing.T) {
	for _, raw := range []string{"", "direct", "none", "invalid", "ftp://127.0.0.1:21"} {
		if isReusableProxyURL(raw) {
			t.Fatalf("isReusableProxyURL(%q) = true, want false", raw)
		}
	}
	if !isReusableProxyURL("SOCKS5://127.0.0.1:1080") {
		t.Fatal("uppercase SOCKS5 proxy should be normalized and reusable")
	}
}

func containsText(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}
