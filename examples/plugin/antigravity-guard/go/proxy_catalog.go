package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	proxyAliasMaxRunes = 40
	proxyIDPrefix      = "p_"
)

type proxyCatalog struct {
	key []byte

	mu      sync.RWMutex
	aliases map[string]string
}

type proxyDescriptor struct {
	ID      string
	Alias   string
	Display string
}

func newProxyCatalog() *proxyCatalog {
	key := make([]byte, sha256.Size)
	if _, errRead := rand.Read(key); errRead != nil {
		panic(fmt.Sprintf("create proxy catalog key: %v", errRead))
	}
	return &proxyCatalog{key: key, aliases: make(map[string]string)}
}

func (c *proxyCatalog) describe(raw string) (proxyDescriptor, bool) {
	canonical, reusable := canonicalReusableProxyURL(raw)
	if !reusable {
		return proxyDescriptor{}, false
	}
	proxyID := c.idForCanonical(canonical)
	return proxyDescriptor{
		ID:      proxyID,
		Alias:   c.alias(proxyID),
		Display: maskProxyURL(canonical),
	}, true
}

func (c *proxyCatalog) currentIDs(entries []hostAuthEntry) map[string]struct{} {
	active := make(map[string]struct{})
	for _, entry := range entries {
		if !isAntigravityEntry(entry) || strings.TrimSpace(entry.AuthIndex) == "" {
			continue
		}
		effectiveProxyURL, _ := effectiveProxy(entry, entry.ConfiguredProxyURL)
		descriptor, reusable := c.describe(effectiveProxyURL)
		if reusable {
			active[descriptor.ID] = struct{}{}
		}
	}
	return active
}

func (c *proxyCatalog) reconcile(active map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reconcileLocked(active)
}

func (c *proxyCatalog) setAlias(proxyID, rawAlias string, active map[string]struct{}) (string, error) {
	proxyID = strings.TrimSpace(proxyID)
	if proxyID == "" {
		return "", fmt.Errorf("proxy_id is required")
	}
	if _, exists := active[proxyID]; !exists {
		return "", fmt.Errorf("proxy_id is not a current reusable Antigravity proxy")
	}
	alias, errAlias := normalizeProxyAlias(rawAlias)
	if errAlias != nil {
		return "", errAlias
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.reconcileLocked(active)
	if alias == "" {
		delete(c.aliases, proxyID)
		return "", nil
	}
	for existingID, existingAlias := range c.aliases {
		if existingID != proxyID && strings.EqualFold(existingAlias, alias) {
			return "", fmt.Errorf("proxy alias must be unique ignoring case")
		}
	}
	c.aliases[proxyID] = alias
	return alias, nil
}

func (c *proxyCatalog) alias(proxyID string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.aliases[proxyID]
}

func (c *proxyCatalog) reconcileLocked(active map[string]struct{}) {
	for proxyID := range c.aliases {
		if _, exists := active[proxyID]; !exists {
			delete(c.aliases, proxyID)
		}
	}
}

func (c *proxyCatalog) idForCanonical(canonical string) string {
	digest := hmac.New(sha256.New, c.key)
	digest.Write([]byte(canonical))
	return proxyIDPrefix + base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func canonicalReusableProxyURL(raw string) (string, bool) {
	validated, errValidate := validateProxyURL(raw)
	if errValidate != nil || validated == "" || validated == "direct" {
		return "", false
	}
	parsed, errParse := url.Parse(validated)
	if errParse != nil || parsed.Host == "" {
		return "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), true
}

func normalizeProxyAlias(raw string) (string, error) {
	alias := strings.TrimSpace(raw)
	if alias == "" {
		return "", nil
	}
	if !utf8.ValidString(alias) {
		return "", fmt.Errorf("proxy alias must be valid UTF-8")
	}
	if utf8.RuneCountInString(alias) > proxyAliasMaxRunes {
		return "", fmt.Errorf("proxy alias must not exceed %d Unicode characters", proxyAliasMaxRunes)
	}
	for _, character := range alias {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("proxy alias must not contain control characters")
		}
	}
	return alias, nil
}
