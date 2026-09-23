package main

import (
	"embed"
	"fmt"
	"net/http"
)

//go:embed web/index.html web/styles.css web/settings.css web/credentials.css web/api.js web/format.js web/search.js web/proxy.js web/bulk-quota.js web/settings.js web/codex.js web/app.js web/bulk-quota-init.js
var webAssets embed.FS

func managementRoutes() managementRegistration {
	return managementRegistration{
		Routes: []managementRoute{
			{Method: http.MethodGet, Path: "/plugins/" + pluginID + "/state", Description: "Return Antigravity guard state."},
			{Method: http.MethodPost, Path: "/plugins/" + pluginID + "/settings", Description: "Update in-memory Antigravity 429 protection settings."},
			{Method: http.MethodPost, Path: "/plugins/" + pluginID + "/quota", Description: "Fetch quota for one Antigravity credential."},
			{Method: http.MethodPost, Path: "/plugins/" + pluginID + "/proxy", Description: "Set, force direct, or clear a runtime proxy override."},
			{Method: http.MethodPost, Path: "/plugins/" + pluginID + "/proxy/alias", Description: "Set or clear an in-memory alias for a current Antigravity proxy."},
			{Method: http.MethodPost, Path: "/plugins/" + pluginID + "/cooldown/clear", Description: "Clear an automatic runtime cooldown."},
			{Method: http.MethodPost, Path: "/plugins/" + pluginID + "/recover", Description: "Manually recover one Antigravity or Codex credential."},
		},
		Resources: []managementResource{
			{Path: "/dashboard", Menu: "Antigravity Guard", Description: "429 cooldown, weekly quota, and proxy management."},
			{Path: "/assets/styles.css", Description: "Antigravity Guard styles."},
			{Path: "/assets/settings.css", Description: "Antigravity Guard runtime settings styles."},
			{Path: "/assets/credentials.css", Description: "Antigravity Guard credential and proxy styles."},
			{Path: "/assets/api.js", Description: "Antigravity Guard Management API client."},
			{Path: "/assets/format.js", Description: "Antigravity Guard display helpers."},
			{Path: "/assets/search.js", Description: "Antigravity Guard search helpers."},
			{Path: "/assets/proxy.js", Description: "Antigravity Guard proxy selection helpers."},
			{Path: "/assets/bulk-quota.js", Description: "Antigravity Guard serial bulk quota helper."},
			{Path: "/assets/settings.js", Description: "Antigravity Guard runtime settings helpers."},
			{Path: "/assets/codex.js", Description: "Codex credential status and recovery controls."},
			{Path: "/assets/app.js", Description: "Antigravity Guard client."},
			{Path: "/assets/bulk-quota-init.js", Description: "Antigravity Guard bulk quota UI wiring."},
		},
	}
}

func resourceResponse(path string) (managementResponse, error) {
	assetPath, contentType := "", ""
	switch path {
	case resourceBasePath + "/dashboard":
		assetPath, contentType = "web/index.html", "text/html; charset=utf-8"
	case resourceBasePath + "/assets/styles.css":
		assetPath, contentType = "web/styles.css", "text/css; charset=utf-8"
	case resourceBasePath + "/assets/settings.css":
		assetPath, contentType = "web/settings.css", "text/css; charset=utf-8"
	case resourceBasePath + "/assets/credentials.css":
		assetPath, contentType = "web/credentials.css", "text/css; charset=utf-8"
	case resourceBasePath + "/assets/api.js":
		assetPath, contentType = "web/api.js", "text/javascript; charset=utf-8"
	case resourceBasePath + "/assets/format.js":
		assetPath, contentType = "web/format.js", "text/javascript; charset=utf-8"
	case resourceBasePath + "/assets/search.js":
		assetPath, contentType = "web/search.js", "text/javascript; charset=utf-8"
	case resourceBasePath + "/assets/proxy.js":
		assetPath, contentType = "web/proxy.js", "text/javascript; charset=utf-8"
	case resourceBasePath + "/assets/bulk-quota.js":
		assetPath, contentType = "web/bulk-quota.js", "text/javascript; charset=utf-8"
	case resourceBasePath + "/assets/settings.js":
		assetPath, contentType = "web/settings.js", "text/javascript; charset=utf-8"
	case resourceBasePath + "/assets/codex.js":
		assetPath, contentType = "web/codex.js", "text/javascript; charset=utf-8"
	case resourceBasePath + "/assets/app.js":
		assetPath, contentType = "web/app.js", "text/javascript; charset=utf-8"
	case resourceBasePath + "/assets/bulk-quota-init.js":
		assetPath, contentType = "web/bulk-quota-init.js", "text/javascript; charset=utf-8"
	default:
		return managementResponse{StatusCode: http.StatusNotFound}, nil
	}
	body, errRead := webAssets.ReadFile(assetPath)
	if errRead != nil {
		return managementResponse{}, fmt.Errorf("read embedded asset %s: %w", assetPath, errRead)
	}
	return managementResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type":            []string{contentType},
			"Cache-Control":           []string{"no-store"},
			"X-Content-Type-Options":  []string{"nosniff"},
			"Referrer-Policy":         []string{"no-referrer"},
			"Content-Security-Policy": []string{"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"},
		},
		Body: body,
	}, nil
}
