package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

type proxyAliasRequest struct {
	ProxyID string `json:"proxy_id"`
	Alias   string `json:"alias"`
}

type proxyAliasResult struct {
	ProxyID    string `json:"proxy_id"`
	ProxyAlias string `json:"proxy_alias"`
}

func (a *application) proxyAliasResponse(raw []byte) managementResponse {
	var request proxyAliasRequest
	if errDecode := json.Unmarshal(raw, &request); errDecode != nil {
		return jsonError(http.StatusBadRequest, "invalid proxy alias request")
	}
	entries, errList := a.host.ListAuths()
	if errList != nil {
		return jsonError(http.StatusBadGateway, "list credentials: "+errList.Error())
	}
	active := a.proxies.currentIDs(entries)
	proxyID := strings.TrimSpace(request.ProxyID)
	alias, errAlias := a.proxies.setAlias(proxyID, request.Alias, active)
	if errAlias != nil {
		return jsonError(http.StatusBadRequest, errAlias.Error())
	}
	return jsonResponse(http.StatusOK, proxyAliasResult{
		ProxyID:    proxyID,
		ProxyAlias: alias,
	})
}
