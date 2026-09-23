"use strict";

(() => {
  function createCodexController(options) {
    const { body, empty, request, showToast, handleError, reloadState, esc, sortCredentials, busyAuth } = options;

    function render(input) {
      if (!body) return;
      const credentials = sortCredentials(input || []);
      if (empty) empty.hidden = credentials.length > 0;
      body.innerHTML = credentials.map(renderRow).join("");
    }

    function renderRow(item) {
      const codex = item.codex || {};
      const statusClass = codex.status === "正常" ? "good" : "bad";
      const cooldownText = item.cooldown
        ? item.cooldown.manual_release_required
          ? "需手动恢复"
          : item.cooldown.remaining_seconds
            ? `${Math.ceil(item.cooldown.remaining_seconds / 60)} 分钟后恢复`
            : "需手动处理"
        : "";
      const busy = busyAuth.has(item.auth_index);
      return `<tr><td><span class="credential-name">${esc(item.name)}</span><span class="subtle">${esc(item.email || item.auth_index)}</span></td><td><span class="badge ${item.effective_disabled ? "bad" : "good"}">${item.effective_disabled ? "已禁用" : "启用"}</span></td><td><span class="badge ${statusClass}">${esc(codex.status || "正常")}</span><span class="subtle">usage_limit ${codex.consecutive_usage_limit || 0} / 2${codex.error_type ? ` · ${esc(codex.error_type)}` : ""}</span></td><td><span class="subtle">周限：${esc(quotaText(codex.weekly))}</span><span class="subtle">5 小时：${esc(quotaText(codex.five_hour))}</span></td><td><span class="subtle">${esc(cooldownText)}</span></td><td><button class="button secondary small" data-action="manual-recover" data-auth="${esc(item.auth_index)}" ${busy ? "disabled" : ""}>${busy ? "恢复中" : "手动恢复"}</button></td></tr>`;
    }

    async function recover(authIndex) {
      busyAuth.add(authIndex);
      render(options.credentials());
      try {
        await request("/recover", { method: "POST", body: JSON.stringify({ auth_index: authIndex }) });
        showToast("Codex 凭证状态已恢复");
        await reloadState();
      } catch (error) {
        handleError(error);
      } finally {
        busyAuth.delete(authIndex);
        render(options.credentials());
      }
    }

    body?.addEventListener("click", (event) => {
      const button = event.target.closest('button[data-action="manual-recover"]');
      if (button) recover(button.dataset.auth);
    });
    return { render, recover };
  }

  function quotaText(window) {
    if (!window) return "尚未获取";
    const usage = window.exhausted ? "已用尽" : `${window.used_percent}%`;
    const reset = window.remaining_seconds ? `${Math.ceil(window.remaining_seconds / 60)} 分钟后刷新` : "刷新时间未知";
    return `${usage} · ${reset}`;
  }

  globalThis.GuardCodex = { createCodexController, quotaText };
})();
