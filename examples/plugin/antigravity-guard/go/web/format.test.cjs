"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

require("./format.js");

const view = globalThis.GuardView;

test("labels mixed proxy sources", () => {
  assert.equal(view.sourceLabel("mixed"), "混合来源");
});

test("translates known restore targets", () => {
  assert.equal(view.restoreTargetLabel("configured priority 14"), "当前配置优先级 14");
  assert.equal(view.restoreTargetLabel("runtime priority 12"), "原运行时优先级 12");
  assert.equal(view.restoreTargetLabel("configured enabled state"), "当前配置的启用状态");
  assert.equal(
    view.restoreTargetLabel("configured priority 14; configured enabled state"),
    "当前配置优先级 14；当前配置的启用状态",
  );
});

test("shows restore phases and manual takeover", () => {
  assert.equal(view.phaseStatus({ phase: "restoring" }), "正在恢复原路由");
  assert.equal(view.phaseStatus({ phase: "retry_wait" }), "恢复失败，等待重试");
  assert.equal(view.phaseStatus({ phase: "cooling", superseded: true }), "已由其他操作接管");
});

test("labels weekly quota cooldowns in Chinese", () => {
  assert.equal(view.cooldownTriggerLabel("weekly_quota_empty"), "Gemini 周限已空");
  assert.equal(view.retrySourceLabel("weekly_quota_reset"), "周限刷新时间");

  const html = view.renderCooldownCell({
    configured_priority: 14,
    configured_disabled: false,
    cooldown: {
      action: "disable",
      trigger: "weekly_quota_empty",
      retry_source: "weekly_quota_reset",
      remaining_seconds: 3600,
    },
  }, {}, Date.now());

  assert.match(html, /Gemini 周限已空/);
  assert.match(html, /周限刷新时间/);
  assert.doesNotMatch(html, /weekly_quota_empty|weekly_quota_reset/);
});

test("labels five-hour quota cooldowns and reset source in Chinese", () => {
  assert.equal(view.cooldownTriggerLabel("five_hour_quota_empty"), "5 小时额度已空");
  assert.equal(view.retrySourceLabel("five_hour_quota_reset"), "5 小时额度刷新时间");

  const html = view.renderCooldownCell({
    configured_priority: 14,
    configured_disabled: false,
    cooldown: {
      action: "disable",
      trigger: "five_hour_quota_empty",
      retry_source: "five_hour_quota_reset",
      remaining_seconds: 3600,
    },
  }, {}, Date.now());

  assert.match(html, /5 小时额度已空/);
  assert.match(html, /5 小时额度刷新时间/);
});

test("labels Codex body reset and fallback cooldown sources", () => {
  assert.equal(view.retrySourceLabel("body.resets_in_seconds"), "Codex 返回的刷新时间");
  assert.equal(view.retrySourceLabel("body.resets_at"), "Codex 返回的刷新时间");
  assert.equal(view.retrySourceLabel("fallback_cooldown"), "插件兜底冷却时间");
});

test("classifies credential routing states for mutually exclusive filters", () => {
  const active = { effective_disabled: false };
  const priorityCooling = { effective_disabled: false, cooldown: { action: "priority" } };
  const disabledCooling = { effective_disabled: true, cooldown: { action: "disable" } };
  const configuredDisabledCooling = {
    configured_disabled: true,
    effective_disabled: true,
    cooldown: { action: "disable" },
  };
  const weeklyQuarantine = {
    effective_disabled: true,
    cooldown: { trigger: "weekly_quota_empty", manual_release_required: true },
  };
  const configuredDisabled = { effective_disabled: true };
  const available = {
    configured_disabled: true,
    effective_disabled: true,
    weekly_quota: { empty: false, remaining_seconds: 900 },
  };

  assert.equal(view.credentialRoutingState(active), "active");
  assert.equal(view.credentialRoutingState(priorityCooling), "cooling");
  assert.equal(view.credentialRoutingState(disabledCooling), "cooling");
  assert.equal(view.credentialRoutingState(configuredDisabledCooling), "disabled");
  assert.equal(view.credentialRoutingState(weeklyQuarantine), "isolated");
  assert.equal(view.credentialRoutingState(configuredDisabled), "disabled");
  assert.equal(view.credentialRoutingState(available), "available");
  assert.equal(view.isCredentialInUse(active), true);
  assert.equal(view.isCredentialInUse(priorityCooling), false);
  assert.equal(view.isCredentialInUse({
    effective_disabled: true,
    cooldown: { trigger: "five_hour_quota_empty" },
  }), true);
  assert.equal(view.isCredentialInUse(available), false);
  assert.equal(view.matchesCredentialStatus(weeklyQuarantine, "isolated"), true);
  assert.equal(view.matchesCredentialStatus(weeklyQuarantine, "disabled"), false);
  assert.equal(view.matchesCredentialStatus(weeklyQuarantine, "cooling"), false);
  assert.equal(view.matchesCredentialStatus(configuredDisabled, "all"), true);
  assert.equal(view.matchesCredentialStatus(available, "available"), true);
  assert.equal(view.matchesCredentialStatus(available, "disabled"), false);
});

test("sorts active 429, cooling, available, isolation, and disabled quota predictably", () => {
  const credentials = [
    { auth_index: "disabled-unknown", effective_disabled: true, effective_priority: 5 },
    { auth_index: "isolated-later", effective_disabled: true, cooldown: { trigger: "weekly_quota_empty", manual_release_required: true }, weekly_quota: { remaining_seconds: 500 } },
    { auth_index: "cooling-later", cooldown: { remaining_seconds: 300 }, effective_priority: 14 },
    { auth_index: "active", usage: { consecutive_429: 0 }, effective_priority: 14 },
    { auth_index: "available-later-reset", effective_disabled: true, weekly_quota: { empty: false, remaining_seconds: 600 }, effective_priority: 3 },
    { auth_index: "available-higher-priority", effective_disabled: true, weekly_quota: { empty: false, remaining_seconds: 900 }, effective_priority: 14 },
    { auth_index: "disabled-empty", effective_disabled: true, weekly_quota: { empty: true, remaining_seconds: 400 }, effective_priority: 3 },
    { auth_index: "isolated-sooner", effective_disabled: true, cooldown: { trigger: "weekly_quota_empty", manual_release_required: true }, weekly_quota: { remaining_seconds: 200 } },
    { auth_index: "active-429", usage: { consecutive_429: 2 }, effective_priority: 14 },
    { auth_index: "cooling-sooner", cooldown: { remaining_seconds: 100 }, effective_priority: 13 },
  ];

  assert.deepEqual(view.sortCredentials(credentials).map((item) => item.auth_index), [
    "active-429",
    "active",
    "cooling-sooner",
    "cooling-later",
    "available-higher-priority",
    "available-later-reset",
    "isolated-sooner",
    "isolated-later",
    "disabled-empty",
    "disabled-unknown",
  ]);
  assert.equal(view.isActiveRateLimited(credentials[8]), true);
  assert.equal(view.isActiveRateLimited(credentials[2]), false);
});

test("renders pre-threshold 429 detection before applying a cooldown", () => {
  const html = view.renderCooldownCell({ usage: { consecutive_429: 2 } }, { consecutive_429_threshold: 3 });
  assert.match(html, /检测到 429/);
  assert.match(html, /连续 2 \/ 3 次/);
});

test("renders weekly quota isolation without automatic restore messaging", () => {
  const html = view.renderCooldownCell({
    configured_priority: 14,
    effective_priority: 13,
    configured_disabled: false,
    cooldown: {
      action: "disable",
      trigger: "weekly_quota_empty",
      manual_release_required: true,
      priority: 13,
      remaining_seconds: 3600,
      restore_target: "configured priority 14; configured enabled state",
      next_restore_attempt: "2099-01-01T00:00:00Z",
    },
  }, { temporary_priority: 13 }, Date.now());

  assert.match(html, /周限隔离/);
  assert.match(html, /已隔离，需手动解除/);
  assert.match(html, /优先级 13 \+ 已禁用/);
  assert.doesNotMatch(html, /即将自动恢复|恢复目标|下次恢复重试|当前配置优先级 14/);
});

test("shows explicit weekly isolation release retries", () => {
  const html = view.renderCooldownCell({
    cooldown: {
      trigger: "weekly_quota_empty",
      manual_release_required: true,
      phase: "retry_wait",
      priority: 13,
      next_restore_attempt: "2099-01-01T00:00:00Z",
      last_error: "temporary failure",
    },
  }, {}, Date.now());

  assert.match(html, /解除失败，等待重试/);
  assert.match(html, /下次恢复重试/);
  assert.match(html, /temporary failure/);
});

test("weekly countdown reaches a stable refresh-time message", () => {
  const originalNow = Date.now;
  Date.now = () => 1_000_000;
  try {
    assert.equal(view.weeklyCountdown(121, 1_000_000), "3 分钟后");
    assert.equal(view.weeklyCountdown(120, 880_000), "刷新时间已到");
  } finally {
    Date.now = originalNow;
  }
});

test("shows reset weekly quota as available instead of not fetched", () => {
  const html = view.renderWeeklyCell({ weekly_quota: {
    empty: false,
    reset_elapsed: true,
    refresh_known: false,
  } }, Date.now());
  assert.match(html, /周限可用/);
  assert.match(html, /按可用处理/);
  assert.doesNotMatch(html, /尚未获取/);
});

test("renders restore target, retry time, and escaped errors", () => {
  const html = view.renderCooldownCell({
    configured_priority: 14,
    configured_disabled: false,
    usage: {},
    cooldown: {
      action: "priority",
      priority: 13,
      trigger: "quota_429",
      phase: "retry_wait",
      restore_target: "configured priority 14",
      next_restore_attempt: "2099-01-01T00:00:00Z",
      last_error: "<restore failed>",
    },
  }, { temporary_priority: 13 }, Date.now());

  assert.match(html, /恢复目标：当前配置优先级 14/);
  assert.match(html, /下次恢复重试/);
  assert.match(html, /&lt;restore failed&gt;/);
});

test("renders the latest completed guard outcome without an active cooldown", () => {
  const restored = view.renderCooldownCell({
    usage: {},
    guard_outcome: {
      outcome: "restored",
      at: "2026-07-26T08:00:00Z",
      restore_target: "configured priority 14",
    },
  });
  const takeover = view.renderGuardOutcome({ outcome: "manual_takeover" });
  assert.match(restored, /最近已恢复/);
  assert.match(restored, /当前配置优先级 14/);
  assert.match(takeover, /已由其他操作接管/);
});
