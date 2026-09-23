package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	pluginID          = "antigravity-guard"
	resourceBasePath  = "/v0/resource/plugins/" + pluginID
	managementAPIPath = "/v0/management/plugins/" + pluginID
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
	UsagePlugin   bool `json:"usage_plugin"`
	ManagementAPI bool `json:"management_api"`
}

type managementRegistration struct {
	Routes    []managementRoute    `json:"routes,omitempty"`
	Resources []managementResource `json:"resources,omitempty"`
}

type managementRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Description string `json:"Description,omitempty"`
}

type managementResource struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

type managementRequest struct {
	Method         string      `json:"Method"`
	Path           string      `json:"Path"`
	Headers        http.Header `json:"Headers"`
	Query          url.Values  `json:"Query"`
	Body           []byte      `json:"Body"`
	HostCallbackID string      `json:"host_callback_id,omitempty"`
}

type managementResponse struct {
	StatusCode int         `json:"StatusCode"`
	Headers    http.Header `json:"Headers"`
	Body       []byte      `json:"Body"`
}

type authListResponse struct {
	Files []hostAuthEntry `json:"files"`
}

type hostAuthEntry struct {
	ID                       string                   `json:"id,omitempty"`
	AuthIndex                string                   `json:"auth_index,omitempty"`
	Name                     string                   `json:"name"`
	Provider                 string                   `json:"provider,omitempty"`
	Type                     string                   `json:"type,omitempty"`
	Label                    string                   `json:"label,omitempty"`
	Email                    string                   `json:"email,omitempty"`
	ProjectID                string                   `json:"project_id,omitempty"`
	Status                   string                   `json:"status,omitempty"`
	StatusMessage            string                   `json:"status_message,omitempty"`
	Disabled                 bool                     `json:"disabled,omitempty"`
	Unavailable              bool                     `json:"unavailable,omitempty"`
	Priority                 int                      `json:"priority,omitempty"`
	Success                  int64                    `json:"success,omitempty"`
	Failed                   int64                    `json:"failed,omitempty"`
	NextRetryAfter           time.Time                `json:"next_retry_after,omitempty"`
	ConfiguredDisabled       bool                     `json:"configured_disabled,omitempty"`
	EffectiveDisabled        bool                     `json:"effective_disabled,omitempty"`
	ConfiguredPriority       int                      `json:"configured_priority,omitempty"`
	EffectivePriority        int                      `json:"effective_priority,omitempty"`
	ConfiguredProxyURL       string                   `json:"configured_proxy_url,omitempty"`
	EffectiveProxyURL        string                   `json:"effective_proxy_url,omitempty"`
	RuntimeOverride          *runtimeOverride         `json:"runtime_override,omitempty"`
	RuntimeOverrideRevisions runtimeOverrideRevisions `json:"runtime_override_revisions"`
}

type runtimeOverride struct {
	Disabled *bool   `json:"disabled,omitempty"`
	Priority *int    `json:"priority,omitempty"`
	ProxyURL *string `json:"proxy_url,omitempty"`
}

type runtimeOverrideRevisions struct {
	Disabled uint64 `json:"disabled"`
	Priority uint64 `json:"priority"`
	ProxyURL uint64 `json:"proxy_url"`
}

func (r runtimeOverrideRevisions) forField(field string) uint64 {
	switch field {
	case "disabled":
		return r.Disabled
	case "priority":
		return r.Priority
	case "proxy_url":
		return r.ProxyURL
	default:
		return 0
	}
}

type runtimeOverrideRequest struct {
	AuthIndex       string                    `json:"auth_index"`
	Disabled        *bool                     `json:"disabled,omitempty"`
	Priority        *int                      `json:"priority,omitempty"`
	ProxyURL        *string                   `json:"proxy_url,omitempty"`
	Clear           []string                  `json:"clear,omitempty"`
	IfRevision      *uint64                   `json:"if_revision,omitempty"`
	IfRevisionField string                    `json:"if_revision_field,omitempty"`
	IfRevisions     *runtimeOverrideRevisions `json:"if_revisions,omitempty"`
}

type runtimeOverrideResponse struct {
	Applied         bool                     `json:"applied"`
	Revision        uint64                   `json:"revision"`
	Revisions       runtimeOverrideRevisions `json:"revisions"`
	Auth            hostAuthEntry            `json:"auth"`
	RuntimeOverride runtimeOverride          `json:"runtime_override"`
}

type hostAuthRequest struct {
	AuthIndex      string      `json:"auth_index"`
	HostCallbackID string      `json:"host_callback_id,omitempty"`
	Method         string      `json:"method"`
	URL            string      `json:"url"`
	Headers        http.Header `json:"headers,omitempty"`
	Body           []byte      `json:"body,omitempty"`
}

type hostAuthResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       []byte      `json:"body,omitempty"`
}
