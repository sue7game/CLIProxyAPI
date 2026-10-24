"use strict";

(() => {
  const {
    esc, isWeeklyQuarantine, credentialRoutingState, isActiveRateLimited,
    renderCooldownCell, renderWeeklyCell,
  } = globalThis.GuardView;
  const { choicesForCredentials, proxyLabel } = globalThis.GuardProxy;
  const planLabels = { free: "Free", pro: "Pro", ultra: "Ultra", "ultra-lite": "Ultra Lite" };

  /** Render cached subscription metadata without changing credential state. */
  function renderSubscription(subscription) {
    if (!subscription?.found) {
      return `<div class="credential-subscription">${subscription?.last_error
        ? renderSubscriptionError("订阅查询失败", subscription.last_error)
        : '<span class="subtle">订阅未获取</span>'}</div>`;
    }
    const label = planLabels[subscription.plan]
      || `未知套餐 · ${subscription.tier_name || subscription.tier_id || "未知"}`;
    const details = [subscription.tier_name, subscription.tier_id];
    if (subscription.updated_at) details.push(`获取于 ${new Date(subscription.updated_at).toLocaleString()}`);
    const stale = subscription.last_error
      ? renderSubscriptionError("更新失败 · 保留上次结果", subscription.last_error)
      : "";
    return `<div class="credential-subscription"><span class="badge subscription-label" title="${esc(details.filter(Boolean).join(" · "))}">订阅 · ${esc(label)}</span>${stale}</div>`;
  }

  function renderSubscriptionError(label, error) {
    return `<span class="subtle subscription-error" tabindex="0" title="${esc(error)}" aria-label="${esc(`${label}：${error}`)}">${label}</span>`;
  }

  function proxyChoiceOptions(item, context) {
    const selected = context.proxyChoices.get(item.auth_index) || "";
    return choicesForCredentials(context.credentials).map((option) =>
      `<option value="${esc(option.value)}" ${selected === option.value ? "selected" : ""}>${esc(option.label)}</option>`).join("");
  }

  function renderRoute(item) {
    const changed = item.configured_priority !== item.effective_priority;
    const priority = `${item.configured_priority}${changed ? ` → ${item.effective_priority}` : ""}`;
    return item.effective_disabled
      ? `<span class="badge bad">已禁用</span><span class="subtle">优先级 ${priority}</span>`
      : `<span class="priority ${changed ? "changed" : ""}">${priority}</span>`;
  }

  /** Render one Antigravity credential with its existing controls and metadata. */
  function renderCredentialRow(item, context) {
    const busy = context.busyAuth.has(item.auth_index);
    const cooldown = item.cooldown;
    const routingState = credentialRoutingState(item);
    const rowClass = isActiveRateLimited(item) ? "credential-rate-limited" : "";
    const cooldownCell = renderCooldownCell(item, context.configuration, context.loadedAt);
    const weeklyCell = renderWeeklyCell(item, context.loadedAt);
    const lastActivity = item.last_request
      ? `${new Date(item.last_request).toLocaleString()}${item.last_model ? ` · ${item.last_model}` : ""}`
      : "本进程未使用";
    const releaseLabel = isWeeklyQuarantine(cooldown) ? "解除隔离" : "解除冷却";
    return `<tr class="${rowClass}" data-routing-state="${routingState}">
      <td class="check-cell"><input class="row-select" type="checkbox" data-auth="${esc(item.auth_index)}" ${context.selected.has(item.auth_index) ? "checked" : ""} aria-label="选择 ${esc(item.name)}"></td>
      <td><span class="credential-name">${esc(item.name)}</span><span class="subtle">${esc(item.email || item.label || item.auth_index)}</span>${renderSubscription(item.subscription)}</td>
      <td><div class="cell-stack">${renderRoute(item)}<span class="subtle">${esc(item.status || "unknown")}</span></div></td>
      <td><div class="cell-stack">${cooldownCell}</div></td>
      <td><div class="cell-stack">${weeklyCell}</div></td>
      <td><span class="proxy-value">${esc(proxyLabel(item))}</span><div class="proxy-picker"><select class="proxy-choice" data-auth="${esc(item.auth_index)}" aria-label="为 ${esc(item.name)} 选择代理" ${busy ? "disabled" : ""}>${proxyChoiceOptions(item, context)}</select><button class="button secondary small" data-action="apply-proxy-choice" data-auth="${esc(item.auth_index)}" ${busy ? "disabled" : ""}>应用</button></div></td>
      <td><span class="usage-line">成功 <strong>${item.usage?.success || 0}</strong> · 失败 ${item.usage?.failed || 0} · 429 ${item.usage?.rate_limited || 0}</span><span class="subtle">${esc(lastActivity)}</span></td>
      <td><div class="actions"><button class="button secondary small" data-action="quota" data-auth="${esc(item.auth_index)}" title="获取额度并查询订阅" ${busy ? "disabled" : ""}>${busy ? "获取中" : "获取额度"}</button>${cooldown ? `<button class="button danger small" data-action="clear-cooldown" data-auth="${esc(item.auth_index)}" ${busy ? "disabled" : ""}>${releaseLabel}</button>` : ""}<button class="button secondary small" data-action="manual-recover" data-auth="${esc(item.auth_index)}" ${busy ? "disabled" : ""}>${busy ? "恢复中" : "手动恢复"}</button></div></td>
    </tr>`;
  }

  globalThis.GuardCredentials = { renderCredentialRow, renderSubscription };
})();
