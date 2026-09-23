"use strict";

(() => {
  function countdown(initialSeconds, loadedAt = 0) {
    const elapsed = loadedAt ? Math.floor((Date.now() - loadedAt) / 1000) : 0;
    const seconds = Math.max(0, Number(initialSeconds || 0) - elapsed);
    if (seconds <= 0) return "即将恢复";
    const totalMinutes = Math.max(1, Math.ceil(seconds / 60));
    const days = Math.floor(totalMinutes / 1440);
    const hours = Math.floor((totalMinutes % 1440) / 60);
    const minutes = totalMinutes % 60;
    if (days) return `${days} 天 ${hours} 小时 ${minutes} 分钟后`;
    if (hours) return `${hours} 小时 ${minutes} 分钟后`;
    return `${minutes} 分钟后`;
  }

  function weeklyCountdown(initialSeconds, loadedAt = 0) {
    const elapsed = loadedAt ? Math.floor((Date.now() - loadedAt) / 1000) : 0;
    const seconds = Math.max(0, Number(initialSeconds || 0) - elapsed);
    if (seconds <= 0) return "刷新时间已到";
    return countdown(seconds);
  }

  function sourceLabel(source) {
    const labels = {
      runtime: "临时代理",
      runtime_direct: "强制直连",
      credential: "凭证配置",
      global: "全局代理",
      direct: "直连",
      mixed: "混合来源",
    };
    return labels[source] || source || "未知";
  }

  function esc(value) {
    const replacements = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return String(value ?? "").replace(/[&<>"']/g, (character) => replacements[character]);
  }

  function restoreTargetLabel(value) {
    const target = String(value || "").trim();
    if (target.includes(";")) {
      return target.split(";")
        .map((part) => restoreTargetLabel(part))
        .filter(Boolean)
        .join("；");
    }
    const priority = target.match(/^(configured|runtime) priority (-?\d+)$/i);
    if (priority) return `${priority[1].toLowerCase() === "runtime" ? "原运行时" : "当前配置"}优先级 ${priority[2]}`;
    const labels = {
      "configured enabled state": "当前配置的启用状态",
      "configured disabled state": "当前配置的禁用状态",
      "runtime disabled": "原运行时禁用状态",
      "runtime enabled": "原运行时启用状态",
    };
    return labels[target.toLowerCase()] || target;
  }

  function cooldownTriggerLabel(trigger) {
    const labels = {
      quota_429: "额度 429",
      weekly_quota_empty: "Gemini 周限已空",
      five_hour_quota_empty: "5 小时额度已空",
      codex_usage_limit: "Codex 额度耗尽",
      codex_401: "Codex 401 已禁用",
    };
    return labels[trigger] || "连续 429";
  }

  function retrySourceLabel(source) {
    if (source === "weekly_quota_reset") return "周限刷新时间";
    if (source === "five_hour_quota_reset") return "5 小时额度刷新时间";
    if (source === "codex_weekly_reset") return "Codex 周限刷新时间";
    if (source === "codex_five_hour_reset") return "Codex 5 小时刷新时间";
    if (source === "body.resets_in_seconds" || source === "body.resets_at") return "Codex 返回的刷新时间";
    if (source === "fallback_cooldown") return "插件兜底冷却时间";
    return source || "";
  }

  function isWeeklyQuarantine(cooldown) {
    return cooldown?.trigger === "weekly_quota_empty" && cooldown?.manual_release_required === true;
  }

  function hasAvailableWeeklyQuota(item) {
    return item?.weekly_quota?.empty === false;
  }

  function credentialRoutingState(item) {
    if (isWeeklyQuarantine(item?.cooldown)) return "isolated";
    if (item?.configured_disabled && item?.cooldown) return "disabled";
    if (item?.cooldown) return "cooling";
    if (item?.configured_disabled || item?.effective_disabled) {
      return hasAvailableWeeklyQuota(item) ? "available" : "disabled";
    }
    return "active";
  }

  function matchesCredentialStatus(item, selectedStatus) {
    return selectedStatus === "all" || credentialRoutingState(item) === selectedStatus;
  }

  function isCredentialInUse(item) {
    return credentialRoutingState(item) === "active"
      || item?.cooldown?.trigger === "five_hour_quota_empty";
  }

  function isActiveRateLimited(item) {
    return credentialRoutingState(item) === "active" && Number(item?.usage?.consecutive_429 || 0) > 0;
  }

  function compareRecoveryTime(left, right, field) {
    const leftValue = Number(left?.[field]);
    const rightValue = Number(right?.[field]);
    const leftKnown = Number.isFinite(leftValue);
    const rightKnown = Number.isFinite(rightValue);
    if (leftKnown !== rightKnown) return leftKnown ? -1 : 1;
    if (leftKnown && leftValue !== rightValue) return leftValue - rightValue;
    return 0;
  }

  function compareCredentialNames(left, right) {
    const leftName = String(left?.name || left?.email || left?.auth_index || "");
    const rightName = String(right?.name || right?.email || right?.auth_index || "");
    return leftName.localeCompare(rightName, "zh-CN", { sensitivity: "base" });
  }

  function compareCredentials(left, right) {
    const stateOrder = { active: 0, cooling: 1, available: 2, isolated: 3, disabled: 4 };
    const leftState = credentialRoutingState(left);
    const rightState = credentialRoutingState(right);
    if (leftState !== rightState) return stateOrder[leftState] - stateOrder[rightState];

    if (leftState === "active") {
      const left429 = Number(left?.usage?.consecutive_429 || 0);
      const right429 = Number(right?.usage?.consecutive_429 || 0);
      if (left429 !== right429) return right429 - left429;
    }

    if (leftState === "cooling") {
      const cooldownOrder = compareRecoveryTime(left?.cooldown, right?.cooldown, "remaining_seconds");
      if (cooldownOrder !== 0) return cooldownOrder;
    }

    if (leftState === "isolated") {
      const resetOrder = compareRecoveryTime(left?.weekly_quota, right?.weekly_quota, "remaining_seconds");
      if (resetOrder !== 0) return resetOrder;
    }

    if (leftState === "disabled") {
      const leftEmpty = left?.weekly_quota?.empty === true;
      const rightEmpty = right?.weekly_quota?.empty === true;
      if (leftEmpty !== rightEmpty) return leftEmpty ? -1 : 1;
      if (leftEmpty) {
        const resetOrder = compareRecoveryTime(left.weekly_quota, right.weekly_quota, "remaining_seconds");
        if (resetOrder !== 0) return resetOrder;
      }
    }

    const leftPriority = Number(left?.effective_priority || left?.configured_priority || 0);
    const rightPriority = Number(right?.effective_priority || right?.configured_priority || 0);
    if (leftPriority !== rightPriority) return rightPriority - leftPriority;
    return compareCredentialNames(left, right);
  }

  function sortCredentials(credentials) {
    return [...(credentials || [])].sort(compareCredentials);
  }

  function phaseStatus(cooldown, loadedAt) {
    const phase = String(cooldown?.phase || "").toLowerCase();
    if (isWeeklyQuarantine(cooldown)) {
      if (cooldown?.pending || phase === "applying") return "隔离写入中";
      if (phase === "restoring") return "正在解除隔离";
      if (["retry_wait", "restore_retry"].includes(phase) || cooldown?.last_error) return "解除失败，等待重试";
      return "已隔离，需手动解除";
    }

    if (cooldown.trigger === "codex_401") {
      return `<span class="badge bad">Codex 401 已禁用</span><span class="subtle">需手动恢复凭证</span>`;
    }
    if (cooldown?.superseded || phase === "manual_takeover") return "已由其他操作接管";
    if (cooldown?.pending || phase === "applying") return "冷却写入中";
    if (phase === "restoring") return "正在恢复原路由";
    if (["retry_wait", "restore_retry"].includes(phase)) return "恢复失败，等待重试";
    if (phase === "restored") return "已恢复原路由";
    if (phase === "apply_failed") return "冷却写入失败";
    if (cooldown?.last_error) return "恢复失败，正在重试";
    return countdown(cooldown?.remaining_seconds, loadedAt);
  }

  function nextRestoreAttempt(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    const seconds = Math.max(0, Math.ceil((date.getTime() - Date.now()) / 1000));
    return `下次恢复重试：${date.toLocaleString()}（${countdown(seconds)}）`;
  }

  function renderGuardOutcome(outcome) {
    if (!["restored", "manual_takeover"].includes(outcome?.outcome)) return "";
    const restored = outcome.outcome === "restored";
    const label = restored ? "最近已恢复" : "已由其他操作接管";
    const target = restoreTargetLabel(outcome.restore_target);
    const date = outcome.at ? new Date(outcome.at) : null;
    const restoredAt = date && !Number.isNaN(date.getTime()) ? date.toLocaleString() : "";
    return `<span class="badge ${restored ? "good" : "warn"}">${label}</span>
      ${target ? `<span class="subtle">恢复目标：${esc(target)}</span>` : ""}
      ${restoredAt ? `<span class="subtle">时间：${esc(restoredAt)}</span>` : ""}`;
  }

  function renderCooldownCell(item, configuration, loadedAt) {
    const cooldown = item?.cooldown;
    if (!cooldown) {
      if (item?.guard_error) return `<span class="badge bad">冷却写入失败</span><span class="subtle">${esc(item.guard_error)}</span>`;
      const outcome = renderGuardOutcome(item?.guard_outcome);
      if (outcome) return outcome;
      const consecutive429 = Number(item?.usage?.consecutive_429 || 0);
      if (consecutive429 > 0) {
        const threshold = Number(configuration?.consecutive_429_threshold || 3);
        return `<span class="badge warn">检测到 429</span><span class="subtle">连续 ${consecutive429} / ${threshold} 次</span>`;
      }
      return `<span class="badge good">正常</span><span class="subtle">连续 0 次</span>`;
    }

    if (isWeeklyQuarantine(cooldown)) {
      const priority = cooldown.priority ?? item?.effective_priority ?? configuration?.temporary_priority;
      const action = priority === undefined || priority === null
        ? "指定优先级 + 已禁用"
        : `优先级 ${priority} + 已禁用`;
      const phase = cooldown.phase || "weekly_quarantine";
      const nextAttempt = ["retry_wait", "restore_retry"].includes(phase)
        ? nextRestoreAttempt(cooldown.next_restore_attempt)
        : "";
      return `<span class="badge bad">周限隔离</span>
        <span class="subtle cooldown-phase" data-phase="${esc(phase)}">${esc(phaseStatus(cooldown, loadedAt))}</span>
        <span class="subtle">${esc(action)}</span>
        ${nextAttempt ? `<span class="subtle">${esc(nextAttempt)}</span>` : ""}
        ${cooldown.last_error ? `<span class="subtle error-text">${esc(cooldown.last_error)}</span>` : ""}`;
    }

    const action = cooldown.action === "priority"
      ? `临时优先级 ${cooldown.priority ?? configuration?.temporary_priority}`
      : "临时禁用";
    const fallbackTarget = cooldown.action === "priority"
      ? `当前配置优先级 ${item.configured_priority}`
      : item.configured_disabled ? "当前配置保持禁用" : "恢复启用";
    const target = restoreTargetLabel(cooldown.restore_target) || fallbackTarget;
    const nextAttempt = nextRestoreAttempt(cooldown.next_restore_attempt);
    const takeover = cooldown.superseded || cooldown.phase === "manual_takeover";
    const phase = takeover ? "manual_takeover" : cooldown.phase || "active";
    const retrySource = retrySourceLabel(cooldown.retry_source);
    return `<span class="badge warn">${esc(cooldownTriggerLabel(cooldown.trigger))}</span>
      <span class="subtle cooldown-phase" data-phase="${esc(phase)}">${esc(phaseStatus(cooldown, loadedAt))}</span>
      <span class="subtle">${esc(action)}${retrySource ? ` · ${esc(retrySource)}` : ""}</span>
      <span class="subtle">${takeover ? "自动恢复已停止" : `恢复目标：${esc(target)}`}</span>
      ${nextAttempt ? `<span class="subtle">${esc(nextAttempt)}</span>` : ""}
      ${cooldown.last_error ? `<span class="subtle error-text">${esc(cooldown.last_error)}</span>` : ""}`;
  }

  function renderWeeklyCell(item, loadedAt) {
    const weekly = item?.weekly_quota;
    if (!weekly) {
      return item?.quota_error
        ? `<span class="badge warn">查询失败</span><span class="subtle">${esc(item.quota_error)}</span>`
        : `<span class="subtle">尚未获取</span>`;
    }

    const refresh = weekly.reset_elapsed
      ? `<span class="subtle">周限已到刷新时间，当前按可用处理</span>`
      : weekly.refresh_known
      ? `<span class="subtle countdown weekly-countdown" data-seconds="${weekly.remaining_seconds || 0}">${esc(weeklyCountdown(weekly.remaining_seconds, loadedAt))}</span>`
      : `<span class="subtle">刷新时间未知</span>`;
    const groups = esc((weekly.groups || []).join("、") || "Gemini 周限");
    const recentError = item.quota_error
      ? `<span class="subtle error-text">最近查询失败：${esc(item.quota_error)}</span>`
      : "";
    if (weekly.empty) return `<span class="badge bad">周限已空</span><span class="subtle">${groups}</span>${refresh}${recentError}`;
    return `<span class="badge good">周限可用</span><span class="subtle">${groups}</span>${refresh}${recentError}`;
  }

  globalThis.GuardView = {
    countdown,
    weeklyCountdown,
    sourceLabel,
    esc,
    restoreTargetLabel,
    cooldownTriggerLabel,
    retrySourceLabel,
    isWeeklyQuarantine,
    hasAvailableWeeklyQuota,
    credentialRoutingState,
    matchesCredentialStatus,
    isCredentialInUse,
    isActiveRateLimited,
    compareCredentials,
    sortCredentials,
    phaseStatus,
    nextRestoreAttempt,
    renderGuardOutcome,
    renderCooldownCell,
    renderWeeklyCell,
  };
})();
