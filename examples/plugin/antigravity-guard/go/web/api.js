"use strict";

(() => {
  const API_BASE = "/v0/management/plugins/antigravity-guard";
  const SESSION_KEY = "antigravityGuard.managementKey";

  function managementKey() {
    return sessionStorage.getItem(SESSION_KEY) || "";
  }

  function saveManagementKey(value) {
    sessionStorage.setItem(SESSION_KEY, String(value || "").trim());
  }

  function clearManagementKey() {
    sessionStorage.removeItem(SESSION_KEY);
  }

  async function request(path, options = {}) {
    const headers = { "X-Management-Key": managementKey(), ...(options.headers || {}) };
    if (options.body) headers["Content-Type"] = "application/json";
    const response = await fetch(`${API_BASE}${path}`, { ...options, headers, cache: "no-store" });
    const text = await response.text();
    let payload = {};
    try { payload = text ? JSON.parse(text) : {}; } catch { payload = { error: text || `HTTP ${response.status}` }; }
    if (!response.ok) {
      const error = new Error(payload.error || `HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  globalThis.GuardAPI = { request, managementKey, saveManagementKey, clearManagementKey };
})();
