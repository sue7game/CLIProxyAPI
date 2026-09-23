"use strict";

(() => {
  function proxyAddress(item) {
    return String(item?.effective_proxy || item?.proxy || "未知代理");
  }

  function proxyKey(item) {
    const proxyID = String(item?.proxy_id || "").trim();
    const source = String(item?.proxy_source || "").trim()
      || String(item?.source || "").trim()
      || "unknown";
    return proxyID || `legacy:${source}:${proxyAddress(item)}`;
  }

  function shortProxyID(proxyID) {
    const value = String(proxyID || "").trim();
    return value ? `#${value.slice(-6)}` : "";
  }

  function proxyLabel(item) {
    const alias = String(item?.proxy_alias || "").trim();
    const marker = shortProxyID(item?.proxy_id);
    if (alias) return alias;
    if (!marker) return proxyAddress(item);
    return `代理 ${marker} · ${proxyAddress(item)}`;
  }

  function filterOptions(groups) {
    return (groups || []).map((group) => ({
      value: proxyKey(group),
      label: proxyLabel(group),
    })).sort((left, right) => left.label.localeCompare(right.label, "zh-CN"));
  }

  function matchesProxy(item, selectedProxy) {
    return selectedProxy === "all" || proxyKey(item) === selectedProxy;
  }

  function choicesForCredentials(credentials) {
    const choices = [{ value: "", label: "选择代理操作" }];
    const seen = new Set();
    for (const source of credentials || []) {
      if (!source.proxy_reusable) continue;
      const key = proxyKey(source);
      if (seen.has(key)) continue;
      seen.add(key);
      choices.push({
        value: `copy:${source.auth_index}`,
        label: `${proxyLabel(source)} · 来源 ${source.name}`,
      });
    }
    choices.push(
      { value: "direct", label: "强制直连" },
      { value: "clear", label: "清除覆盖并恢复配置" },
    );
    return choices;
  }

  function actionPayload(authIndex, choice) {
    if (!choice) return null;
    if (choice.startsWith("copy:")) {
      return {
        auth_index: authIndex,
        mode: "copy",
        source_auth_index: choice.slice("copy:".length),
      };
    }
    if (["direct", "clear"].includes(choice)) {
      return { auth_index: authIndex, mode: choice };
    }
    return null;
  }

  function aliasPayload(proxyID, alias) {
    const normalizedID = String(proxyID || "").trim();
    const normalizedAlias = String(alias || "").trim();
    if (!normalizedID) throw new Error("代理标识无效，请刷新页面后重试");
    if ([...normalizedAlias].length > 40) throw new Error("代理别名不能超过 40 个字符");
    if (/[\u0000-\u001f\u007f]/.test(normalizedAlias)) throw new Error("代理别名不能包含控制字符");
    return { proxy_id: normalizedID, alias: normalizedAlias };
  }

  function postProxyAlias(request, payload) {
    return request("/proxy/alias", { method: "POST", body: JSON.stringify(payload) });
  }

  function renderProxyFilter(filter, groups, esc) {
    const current = filter.value;
    const options = filterOptions(groups);
    filter.innerHTML = `<option value="all">全部代理</option>${options.map((option) =>
      `<option value="${esc(option.value)}">${esc(option.label)}</option>`).join("")}`;
    filter.value = options.some((option) => option.value === current) ? current : "all";
  }

  function renderAliasEditor(group, busy, esc) {
    if (!group.proxy_id) return `<p class="proxy-alias-unavailable">直连路线无需设置别名。</p>`;
    const alias = String(group.proxy_alias || "");
    return `<form class="proxy-alias-form" data-proxy-id="${esc(group.proxy_id)}">
      <label>代理别名（最多 40 个字符）</label>
      <div>
        <input name="alias" value="${esc(alias)}" placeholder="例如：美国住宅 01" aria-label="代理别名 ${esc(shortProxyID(group.proxy_id))}" ${busy ? "disabled" : ""}>
        <button class="button secondary small" type="submit" ${busy ? "disabled" : ""}>${busy ? "保存中…" : "保存"}</button>
        ${alias ? `<button class="button ghost small" type="button" data-action="clear-proxy-alias" ${busy ? "disabled" : ""}>清除</button>` : ""}
      </div>
    </form>`;
  }

  function inUseCounts(credentials, isCredentialInUse) {
    const counts = new Map();
    for (const credential of credentials || []) {
      if (!isCredentialInUse(credential)) continue;
      const key = proxyKey(credential);
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    return counts;
  }

  function proxyCardHTML(group, inUse, busy, esc, sourceLabel) {
    const marker = shortProxyID(group.proxy_id);
    const title = String(group.proxy_alias || "").trim() || (marker ? `代理 ${marker}` : sourceLabel(group.source));
    const address = proxyAddress(group);
    const addressLine = marker || address !== title ? `<code>${esc(address)}</code>` : "";
    return `<article class="proxy-card">
      <header>
        <div class="proxy-identity"><strong>${esc(title)}</strong>${addressLine}${group.proxy_alias ? `<small>${esc(marker)}</small>` : ""}</div>
        <span class="source">${esc(sourceLabel(group.source))}</span>
      </header>
      <div class="proxy-stats">
        <span>配置凭证<strong>${group.credentials}</strong></span>
        <span>使用/5 小时冷却<strong>${inUse}</strong></span>
      </div>
      ${renderAliasEditor(group, busy, esc)}
    </article>`;
  }

  function renderProxyGroups(element, groups, credentials, isCredentialInUse, isBusy, esc, sourceLabel) {
    if (!groups.length) {
      element.innerHTML = `<div class="empty-state"><strong>暂无代理数据</strong><span>连接凭证后会按有效代理分组。</span></div>`;
      return;
    }
    const usage = inUseCounts(credentials, isCredentialInUse);
    element.innerHTML = groups.map((group) =>
      proxyCardHTML(group, usage.get(proxyKey(group)) || 0, isBusy(group.proxy_id), esc, sourceLabel)).join("");
  }

  function bindAliasEvents(groups, saveAlias) {
    groups.addEventListener("submit", (event) => {
      const form = event.target.closest(".proxy-alias-form");
      if (!form) return;
      event.preventDefault();
      saveAlias(form.dataset.proxyId, form.querySelector('[name="alias"]').value);
    });
    groups.addEventListener("click", (event) => {
      const button = event.target.closest('[data-action="clear-proxy-alias"]');
      if (!button) return;
      const form = button.closest(".proxy-alias-form");
      saveAlias(form.dataset.proxyId, "");
    });
  }

  function setAliasFormBusy(groups, proxyID, busy) {
    const form = [...groups.querySelectorAll(".proxy-alias-form")]
      .find((candidate) => candidate.dataset.proxyId === proxyID);
    if (!form) return;
    form.querySelectorAll("input, button").forEach((control) => { control.disabled = busy; });
    const submit = form.querySelector('[type="submit"]');
    if (submit) submit.textContent = busy ? "保存中…" : "保存";
  }

  function createProxyController({ filter, groups, request, showToast, handleError, reloadState, esc, sourceLabel, isCredentialInUse }) {
    let data = null;
    let globalBusy = false;
    const busyProxyIDs = new Set();
    const renderGroups = () => renderProxyGroups(
      groups,
      data?.proxy_groups || [],
      data?.credentials || [],
      isCredentialInUse,
      (proxyID) => globalBusy || busyProxyIDs.has(proxyID),
      esc,
      sourceLabel,
    );

    async function saveAlias(proxyID, alias) {
      let payload;
      try {
        payload = aliasPayload(proxyID, alias);
      } catch (error) {
        showToast(error.message, true);
        return;
      }
      busyProxyIDs.add(payload.proxy_id);
      setAliasFormBusy(groups, payload.proxy_id, true);
      let saved = false;
      try {
        await postProxyAlias(request, payload);
        saved = true;
        showToast(payload.alias ? "代理别名已保存" : "代理别名已清除");
        await reloadState();
      } catch (error) {
        handleError(error);
      } finally {
        busyProxyIDs.delete(payload.proxy_id);
        if (saved) renderGroups();
        else setAliasFormBusy(groups, payload.proxy_id, false);
      }
    }

    bindAliasEvents(groups, saveAlias);

    return {
      render(nextData) {
        data = nextData;
        renderProxyFilter(filter, data?.proxy_groups, esc);
        renderGroups();
      },
      matches(item) {
        return matchesProxy(item, filter.value);
      },
      setGlobalBusy(value) {
        globalBusy = Boolean(value);
        renderGroups();
      },
      isBusy() {
        return globalBusy || busyProxyIDs.size > 0;
      },
    };
  }

  globalThis.GuardProxy = {
    proxyKey,
    shortProxyID,
    proxyLabel,
    filterOptions,
    matchesProxy,
    choicesForCredentials,
    actionPayload,
    aliasPayload,
    postProxyAlias,
    inUseCounts,
    proxyCardHTML,
    createProxyController,
  };
})();
