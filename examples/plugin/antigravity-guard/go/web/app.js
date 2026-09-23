"use strict";

const { request: api, managementKey, saveManagementKey, clearManagementKey } = globalThis.GuardAPI;
const {
  weeklyCountdown,
  sourceLabel,
  esc,
  isWeeklyQuarantine,
  credentialRoutingState,
  matchesCredentialStatus,
  isCredentialInUse,
  isActiveRateLimited,
  sortCredentials,
  renderCooldownCell,
  renderWeeklyCell,
} = globalThis.GuardView;
const { matchesCredential } = globalThis.GuardSearch;
const { choicesForCredentials, actionPayload, proxyLabel, createProxyController } = globalThis.GuardProxy;
const { createSettingsController } = globalThis.GuardSettings;
const { createCodexController } = globalThis.GuardCodex;

const ui = {
  keyPanel: document.querySelector("#keyPanel"),
  keyForm: document.querySelector("#keyForm"),
  keyInput: document.querySelector("#managementKey"),
  dashboard: document.querySelector("#dashboard"),
  connection: document.querySelector("#connectionState"),
  connectionText: document.querySelector("#connectionText"),
  search: document.querySelector("#searchInput"),
  status: document.querySelector("#credentialStatusFilters"),
  proxy: document.querySelector("#proxyFilter"),
  refresh: document.querySelector("#refreshButton"),
  proxyGroups: document.querySelector("#proxyGroups"),
  body: document.querySelector("#credentialsBody"),
  codexBody: document.querySelector("#codexCredentialsBody"),
  codexEmpty: document.querySelector("#codexEmptyState"),
  empty: document.querySelector("#emptyState"),
  resultCount: document.querySelector("#resultCount"),
  selectVisible: document.querySelector("#selectVisible"),
  selectedCount: document.querySelector("#selectedCount"),
  proxyInput: document.querySelector("#proxyInput"),
  setProxy: document.querySelector("#setProxyButton"),
  direct: document.querySelector("#directButton"),
  clearProxy: document.querySelector("#clearProxyButton"),
  toast: document.querySelector("#toast"),
};

const state = {
  data: null,
  loadedAt: 0,
  selected: new Set(),
  proxyChoices: new Map(),
  busyAuth: new Set(),
  busy: false,
  loading: null,
  statusFilter: "all",
};

const proxyController = createProxyController({
  filter: ui.proxy,
  groups: ui.proxyGroups,
  request: api,
  showToast,
  handleError: handleAPIError,
  reloadState: () => loadState({ force: true }),
  esc,
  sourceLabel,
  isCredentialInUse,
});

const guardSettings = createSettingsController({
  request: api,
  showToast,
  handleError: handleAPIError,
  async onApplied() {
    await loadState({ force: true });
  },
});

const codexController = createCodexController({
  body: ui.codexBody,
  empty: ui.codexEmpty,
  request: api,
  showToast,
  handleError: handleAPIError,
  reloadState: () => loadState({ force: true }),
  credentials: () => state.data?.codex_credentials || [],
  esc,
  sortCredentials,
  busyAuth: state.busyAuth,
});

async function loadState({ silent = false, force = false } = {}) {
  if (state.loading) {
    try { await state.loading; } catch { /* The active caller reports the error. */ }
    if (!force) return;
  }
  if (!silent) setBusy(true);
  const request = api("/state");
  state.loading = request;
  try {
    state.data = await request;
    state.loadedAt = Date.now();
    removeMissingSelections();
    setConnection("online", "已连接 · 30 秒自动刷新");
    ui.keyPanel.hidden = true;
    ui.dashboard.hidden = false;
    renderAll();
  } catch (error) {
    handleAPIError(error, silent);
  } finally {
    if (state.loading === request) state.loading = null;
    if (!silent) setBusy(false);
  }
}

function renderAll() {
  if (!state.data) return;
  guardSettings.render(state.data.configuration);
  renderSummary();
  proxyController.render(state.data);
  renderCredentials();
  codexController.render(state.data?.codex_credentials || []);
  renderBulkState();
}

function renderSummary() {
  const credentials = state.data.credentials || [];
  const cooling = credentials.filter((item) => item.cooldown).length;
  const weekly = credentials.filter((item) => item.weekly_quota?.empty).length;
  const recent = credentials.filter((item) => item.recent).length;
  const rateLimited = credentials.reduce((sum, item) => sum + (item.usage?.rate_limited || 0), 0);
  const configuration = state.data.configuration || {};
  const configuredThreshold = Number(configuration.consecutive_429_threshold);
  const threshold = Number.isSafeInteger(configuredThreshold) && configuredThreshold >= 1
    ? configuredThreshold
    : 3;
  const guardMode = configuration.auto_429_enabled === false
    ? "自动守卫已关闭"
    : configuration.action === "priority"
      ? `自动降至优先级 ${configuration.temporary_priority}`
      : "自动禁用模式";
  setText("metricCredentials", credentials.length);
  setText("metricRecent", `最近使用 ${recent}`);
  setText("metricCooling", cooling);
  setText("metric429", `${guardMode} · 连续 ${threshold} 次后触发 · 累计 ${rateLimited} 次`);
  setText("metricWeekly", weekly);
  setText("metricProxies", (state.data.proxy_groups || []).length);
  setText("metricUpdated", `每 30 秒自动刷新 · ${new Date(state.data.generated_at).toLocaleTimeString()}`);
}

function renderCredentials() {
  const credentials = visibleCredentials();
  ui.resultCount.textContent = `${credentials.length} 个结果`;
  ui.empty.hidden = credentials.length > 0;
  ui.body.innerHTML = credentials.map(renderCredentialRow).join("");
  const visibleSelected = credentials.filter((item) => state.selected.has(item.auth_index)).length;
  ui.selectVisible.checked = credentials.length > 0 && visibleSelected === credentials.length;
  ui.selectVisible.indeterminate = visibleSelected > 0 && visibleSelected < credentials.length;
}

function proxyChoiceOptions(item) {
  const selected = state.proxyChoices.get(item.auth_index) || "";
  return choicesForCredentials(state.data?.credentials).map((option) =>
    `<option value="${esc(option.value)}" ${selected === option.value ? "selected" : ""}>${esc(option.label)}</option>`).join("");
}

function renderCredentialRow(item) {
  const busy = state.busyAuth.has(item.auth_index);
  const cooldown = item.cooldown;
  const routingState = credentialRoutingState(item);
  const rowClass = isActiveRateLimited(item) ? "credential-rate-limited" : "";
  const priorityChanged = item.configured_priority !== item.effective_priority;
  const route = item.effective_disabled
    ? `<span class="badge bad">已禁用</span><span class="subtle">优先级 ${item.configured_priority}${priorityChanged ? ` → ${item.effective_priority}` : ""}</span>`
    : `<span class="priority ${priorityChanged ? "changed" : ""}">${item.configured_priority}${priorityChanged ? ` → ${item.effective_priority}` : ""}</span>`;
  const cooldownCell = renderCooldownCell(item, state.data?.configuration, state.loadedAt);
  const weeklyCell = renderWeeklyCell(item, state.loadedAt);
  const lastActivity = item.last_request
    ? `${new Date(item.last_request).toLocaleString()}${item.last_model ? ` · ${item.last_model}` : ""}`
    : "本进程未使用";
  const releaseLabel = isWeeklyQuarantine(cooldown) ? "解除隔离" : "解除冷却";
  return `<tr class="${rowClass}" data-routing-state="${routingState}">
    <td class="check-cell"><input class="row-select" type="checkbox" data-auth="${esc(item.auth_index)}" ${state.selected.has(item.auth_index) ? "checked" : ""} aria-label="选择 ${esc(item.name)}"></td>
    <td><span class="credential-name">${esc(item.name)}</span><span class="subtle">${esc(item.email || item.label || item.auth_index)}</span></td>
    <td><div class="cell-stack">${route}<span class="subtle">${esc(item.status || "unknown")}</span></div></td>
    <td><div class="cell-stack">${cooldownCell}</div></td>
    <td><div class="cell-stack">${weeklyCell}</div></td>
    <td><span class="proxy-value">${esc(proxyLabel(item))}</span><div class="proxy-picker"><select class="proxy-choice" data-auth="${esc(item.auth_index)}" aria-label="为 ${esc(item.name)} 选择代理" ${busy ? "disabled" : ""}>${proxyChoiceOptions(item)}</select><button class="button secondary small" data-action="apply-proxy-choice" data-auth="${esc(item.auth_index)}" ${busy ? "disabled" : ""}>应用</button></div></td>
    <td><span class="usage-line">成功 <strong>${item.usage?.success || 0}</strong> · 失败 ${item.usage?.failed || 0} · 429 ${item.usage?.rate_limited || 0}</span><span class="subtle">${esc(lastActivity)}</span></td>
    <td><div class="actions"><button class="button secondary small" data-action="quota" data-auth="${esc(item.auth_index)}" ${busy ? "disabled" : ""}>${busy ? "获取中" : "获取额度"}</button>${cooldown ? `<button class="button danger small" data-action="clear-cooldown" data-auth="${esc(item.auth_index)}" ${busy ? "disabled" : ""}>${releaseLabel}</button>` : ""}<button class="button secondary small" data-action="manual-recover" data-auth="${esc(item.auth_index)}" ${busy ? "disabled" : ""}>${busy ? "恢复中" : "手动恢复"}</button></div></td>
  </tr>`;
}

function visibleCredentials() {
  const query = ui.search.value;
  const credentials = (state.data?.credentials || []).filter((item) => {
    if (!matchesCredential(item, query)) return false;
    if (!proxyController.matches(item)) return false;
    return matchesCredentialStatus(item, state.statusFilter);
  });
  return sortCredentials(credentials);
}

function setCredentialStatusFilter(status) {
  if (!["all", "active", "available", "cooling", "isolated", "disabled"].includes(status)) return;
  state.statusFilter = status;
  ui.status.querySelectorAll("[data-status]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.status === status));
  });
  renderCredentials();
}

async function credentialAction(action, authIndex) {
  const credential = (state.data?.credentials || []).find((item) => item.auth_index === authIndex);
  const weeklyQuarantine = isWeeklyQuarantine(credential?.cooldown);
  state.busyAuth.add(authIndex);
  renderCredentials();
  try {
    const path = action === "quota" ? "/quota" : action === "manual-recover" ? "/recover" : "/cooldown/clear";
    await api(path, { method: "POST", body: JSON.stringify({ auth_index: authIndex }) });
    showToast(action === "quota" ? "额度已刷新" : action === "manual-recover" ? "凭证状态已恢复" : weeklyQuarantine ? "隔离已解除" : "冷却已解除");
    await loadState({ force: true });
  } catch (error) {
    handleAPIError(error);
  } finally {
    state.busyAuth.delete(authIndex);
    renderCredentials();
    codexController.render(state.data?.codex_credentials || []);
  }
}

async function applyProxy(mode) {
  const authIndices = [...state.selected];
  if (!authIndices.length) return showToast("请先选择凭证", true);
  const payload = { auth_indices: authIndices, mode };
  if (mode === "set") payload.proxy_url = ui.proxyInput.value.trim();
  setBusy(true);
  try {
    const result = await api("/proxy", { method: "POST", body: JSON.stringify(payload) });
    const updated = Array.isArray(result.updated) ? result.updated : [];
    const failedEntries = Object.entries(result.failed || {});
    const failureDetail = failedEntries.length ? `；${failedEntries[0][0]}：${failedEntries[0][1]}` : "";
    showToast(failedEntries.length ? `已更新 ${updated.length} 个，失败 ${failedEntries.length} 个${failureDetail}` : `已更新 ${updated.length} 个凭证`, failedEntries.length > 0);
    if (mode === "set" && updated.length > 0) ui.proxyInput.value = "";
    await loadState({ force: true });
  } catch (error) {
    handleAPIError(error);
  } finally {
    setBusy(false);
  }
}

async function applyCredentialProxy(authIndex) {
  const choice = state.proxyChoices.get(authIndex) || "";
  if (!choice) return showToast("请先选择代理操作", true);

  const payload = actionPayload(authIndex, choice);
  if (!payload) return showToast("代理操作无效，请重新选择", true);

  state.busyAuth.add(authIndex);
  renderCredentials();
  try {
    await api("/proxy", { method: "POST", body: JSON.stringify(payload) });
    state.proxyChoices.delete(authIndex);
    showToast("凭证代理已更新");
    await loadState({ force: true });
  } catch (error) {
    handleAPIError(error);
  } finally {
    state.busyAuth.delete(authIndex);
    renderCredentials();
  }
}

function removeMissingSelections() {
  const available = new Set((state.data?.credentials || []).map((item) => item.auth_index));
  state.selected.forEach((authIndex) => { if (!available.has(authIndex)) state.selected.delete(authIndex); });
  state.proxyChoices.forEach((choice, authIndex) => {
    const sourceAuthIndex = choice.startsWith("copy:") ? choice.slice("copy:".length) : "";
    if (!available.has(authIndex) || (sourceAuthIndex && !available.has(sourceAuthIndex))) {
      state.proxyChoices.delete(authIndex);
    }
  });
}

function renderBulkState() {
  ui.selectedCount.textContent = state.selected.size;
  [ui.setProxy, ui.direct, ui.clearProxy].forEach((button) => { button.disabled = state.busy || state.selected.size === 0; });
  globalThis.guardBulkQuota?.render(state.selected.size, state.busy);
}

function setBusy(busy) {
  state.busy = busy;
  ui.refresh.disabled = busy;
  guardSettings.setGlobalBusy(busy);
  proxyController.setGlobalBusy(busy);
  renderBulkState();
}

function showKeyPanel() {
  ui.keyPanel.hidden = false;
  ui.dashboard.hidden = true;
  ui.keyInput.value = managementKey();
}

function setConnection(status, text) {
  ui.connection.dataset.state = status;
  ui.connectionText.textContent = text;
}

function handleAPIError(error, silent = false) {
  if (error.status === 401) {
    clearManagementKey();
    showKeyPanel();
    setConnection("error", "管理密钥无效");
  } else if (error.status === 403) {
    setConnection("error", "管理访问被拒绝");
  } else {
    setConnection("error", silent ? "自动刷新失败，等待重试" : "请求失败");
  }
  if (!silent || error.status === 401) showToast(error.message || "请求失败", true);
}

let toastTimer;
function showToast(message, isError = false) {
  clearTimeout(toastTimer);
  ui.toast.textContent = message;
  ui.toast.classList.toggle("error", isError);
  ui.toast.hidden = false;
  toastTimer = setTimeout(() => { ui.toast.hidden = true; }, 4200);
}

function setText(id, value) { document.getElementById(id).textContent = value; }

function refreshWeeklyCountdowns() {
  document.querySelectorAll(".weekly-countdown").forEach((element) => {
    element.textContent = weeklyCountdown(Number(element.dataset.seconds || 0), state.loadedAt);
  });
}

ui.keyForm.addEventListener("submit", (event) => {
  event.preventDefault();
  saveManagementKey(ui.keyInput.value);
  loadState();
});
ui.refresh.addEventListener("click", () => loadState({ force: true }));
ui.search.addEventListener("input", renderCredentials);
ui.status.addEventListener("click", (event) => {
  const button = event.target.closest("[data-status]");
  if (button) setCredentialStatusFilter(button.dataset.status);
});
ui.proxy.addEventListener("change", renderCredentials);
ui.selectVisible.addEventListener("change", () => {
  visibleCredentials().forEach((item) => ui.selectVisible.checked ? state.selected.add(item.auth_index) : state.selected.delete(item.auth_index));
  renderCredentials();
  renderBulkState();
});
ui.body.addEventListener("change", (event) => {
  const proxyChoice = event.target.closest(".proxy-choice");
  if (proxyChoice) {
    if (proxyChoice.value) state.proxyChoices.set(proxyChoice.dataset.auth, proxyChoice.value);
    else state.proxyChoices.delete(proxyChoice.dataset.auth);
    return;
  }
  const checkbox = event.target.closest(".row-select");
  if (!checkbox) return;
  checkbox.checked ? state.selected.add(checkbox.dataset.auth) : state.selected.delete(checkbox.dataset.auth);
  renderBulkState();
});
ui.body.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  if (button.dataset.action === "apply-proxy-choice") {
    applyCredentialProxy(button.dataset.auth);
    return;
  }
  credentialAction(button.dataset.action, button.dataset.auth);
});
ui.setProxy.addEventListener("click", () => applyProxy("set"));
ui.direct.addEventListener("click", () => applyProxy("direct"));
ui.clearProxy.addEventListener("click", () => applyProxy("clear"));

setInterval(() => {
  if (!state.data) return;
  refreshWeeklyCountdowns();
}, 1000);

async function autoRefreshState() {
  const operationBusy = state.busy || state.busyAuth.size > 0 || globalThis.guardBulkQuota?.isBusy() || guardSettings.isBusy() || proxyController.isBusy();
  if (!state.data || operationBusy || state.loading || document.hidden) return;
  await loadState({ silent: true });
}

setInterval(autoRefreshState, 30000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && state.data && Date.now() - state.loadedAt >= 30000) autoRefreshState();
});
if (managementKey()) loadState(); else showKeyPanel();
