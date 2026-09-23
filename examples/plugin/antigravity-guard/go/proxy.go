package main

import (
	"fmt"
	"net/url"
	"strings"
)

func validateProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if isDirectProxyURL(raw) {
		return "direct", nil
	}
	parsed, errParse := url.Parse(raw)
	if errParse != nil || parsed.Host == "" {
		return "", fmt.Errorf("proxy_url must be an absolute proxy URL")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
		return parsed.String(), nil
	default:
		return "", fmt.Errorf("proxy_url scheme must be http, https, socks5, or socks5h")
	}
}

func maskProxyURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "继承配置 / 直连"
	}
	if isDirectProxyURL(raw) {
		return "强制直连"
	}
	parsed, errParse := url.Parse(raw)
	if errParse == nil && parsed.Host != "" {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		return parsed.String()
	}
	return "无效代理地址（已隐藏）"
}

func effectiveProxy(entry hostAuthEntry, configured string) (string, string) {
	if entry.RuntimeOverride != nil && entry.RuntimeOverride.ProxyURL != nil {
		if isDirectProxyURL(*entry.RuntimeOverride.ProxyURL) {
			return "direct", "runtime_direct"
		}
		return normalizedProxyDisplay(*entry.RuntimeOverride.ProxyURL), "runtime"
	}
	if configured != "" {
		if isDirectProxyURL(configured) {
			return "direct", "credential"
		}
		return normalizedProxyDisplay(configured), "credential"
	}
	if entry.EffectiveProxyURL != "" {
		if isDirectProxyURL(entry.EffectiveProxyURL) {
			return "direct", "global"
		}
		return normalizedProxyDisplay(entry.EffectiveProxyURL), "global"
	}
	return "", "direct"
}

func isDirectProxyURL(raw string) bool {
	return strings.EqualFold(strings.TrimSpace(raw), "direct") || strings.EqualFold(strings.TrimSpace(raw), "none")
}

func isReusableProxyURL(raw string) bool {
	proxyURL, errValidate := validateProxyURL(raw)
	return errValidate == nil && proxyURL != "" && proxyURL != "direct"
}

func normalizedProxyDisplay(raw string) string {
	proxyURL, errValidate := validateProxyURL(raw)
	if errValidate == nil && proxyURL != "" {
		return proxyURL
	}
	return strings.TrimSpace(raw)
}
