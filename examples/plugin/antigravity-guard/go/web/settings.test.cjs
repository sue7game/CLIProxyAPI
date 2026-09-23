"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

require("./settings.js");

const {
  normalizeConfiguration,
  createSettingsPayload,
  postSettings,
  cleanupNotice,
  successNotice,
  renderControlState,
} = globalThis.GuardSettings;

test("normalizes a complete runtime configuration", () => {
  assert.deepEqual(normalizeConfiguration({
    auto_429_enabled: false,
    action: "priority",
    temporary_priority: 8,
    consecutive_429_threshold: 5,
  }), {
    auto_429_enabled: false,
    action: "priority",
    temporary_priority: 8,
    consecutive_429_threshold: 5,
  });
});

test("uses safe defaults for missing or invalid configuration", () => {
  assert.deepEqual(normalizeConfiguration({
    action: "unknown",
    temporary_priority: "not-a-number",
    consecutive_429_threshold: 0,
  }), {
    auto_429_enabled: true,
    action: "disable",
    temporary_priority: 13,
    consecutive_429_threshold: 3,
  });
});

test("creates the complete settings request payload", () => {
  assert.deepEqual(createSettingsPayload({
    auto_429_enabled: true,
    action: "priority",
    temporary_priority: " 12 ",
    consecutive_429_threshold: " 4 ",
  }), {
    auto_429_enabled: true,
    action: "priority",
    temporary_priority: 12,
    consecutive_429_threshold: 4,
  });
});

test("posts settings to the runtime endpoint", async () => {
  const calls = [];
  const payload = {
    auto_429_enabled: true,
    action: "disable",
    temporary_priority: 13,
    consecutive_429_threshold: 3,
  };
  const result = await postSettings(async (...args) => {
    calls.push(args);
    return { action: "disable" };
  }, payload);

  assert.deepEqual(calls, [["/settings", {
    method: "POST",
    body: JSON.stringify(payload),
  }]]);
  assert.deepEqual(result, { action: "disable" });
});

test("reports credentials whose runtime restore will be retried", () => {
  assert.equal(cleanupNotice({ failed: { "auth-1": "temporary failure", "auth-2": "temporary failure" } }),
    "守卫已关闭，但有 2 个凭证恢复失败，正在重试。");
  assert.equal(cleanupNotice({ restored: 2 }), "");
});

test("uses distinct success messages when enabling or disabling the guard", () => {
  assert.deepEqual(successNotice(true), {
    feedback: "已应用，将用于后续新触发的 429",
    toast: "429 守卫策略已应用，仅当前进程生效",
  });
  assert.deepEqual(successNotice(false), {
    feedback: "守卫已关闭，已立即尝试恢复受影响凭证的原路由状态",
    toast: "429 守卫已关闭，并已立即尝试恢复原路由状态",
  });
});

test("awaits the applied callback so the dashboard can reload full state", async () => {
  const feedback = { textContent: "", dataset: {} };
  const elements = {
    auto429: { checked: true, disabled: false },
    actionGroup: { disabled: false },
    priority: { value: "13", disabled: false },
    prioritySetting: { dataset: {} },
    threshold: { value: "3", disabled: false },
    thresholdSetting: { dataset: {} },
    submit: { disabled: false, textContent: "" },
    feedback,
    form: {
      querySelector(selector) {
        if (selector.endsWith(":checked")) return { value: "disable" };
        return { checked: false };
      },
    },
  };
  const state = {
    configuration: {
      auto_429_enabled: true,
      action: "disable",
      temporary_priority: 13,
      consecutive_429_threshold: 3,
    },
    globalBusy: false,
    busy: false,
    dirty: true,
    initialized: true,
  };
  const order = [];
  await globalThis.GuardSettings.applySettings({
    request: async () => ({ configuration: state.configuration }),
    showToast: () => order.push("toast"),
    handleError: assert.fail,
    onApplied: async () => {
      await Promise.resolve();
      order.push("reloaded");
    },
  }, elements, state);

  assert.deepEqual(order, ["reloaded", "toast"]);
  assert.equal(feedback.dataset.state, "success");
});

test("disabling the guard confirms that immediate restore was attempted", async () => {
  const feedback = { textContent: "", dataset: {} };
  const elements = {
    auto429: { checked: false, disabled: false },
    actionGroup: { disabled: false },
    priority: { value: "13", disabled: false },
    prioritySetting: { dataset: {} },
    threshold: { value: "3", disabled: false },
    thresholdSetting: { dataset: {} },
    submit: { disabled: false, textContent: "" },
    feedback,
    form: {
      querySelector(selector) {
        if (selector.endsWith(":checked")) return { value: "disable" };
        return { checked: false };
      },
    },
  };
  const state = {
    configuration: {
      auto_429_enabled: true,
      action: "disable",
      temporary_priority: 13,
      consecutive_429_threshold: 3,
    },
    globalBusy: false,
    busy: false,
    dirty: true,
    initialized: true,
  };
  const toasts = [];

  await globalThis.GuardSettings.applySettings({
    request: async () => ({
      configuration: {
        auto_429_enabled: false,
        action: "disable",
        temporary_priority: 13,
        consecutive_429_threshold: 3,
      },
    }),
    showToast: (message) => toasts.push(message),
    handleError: assert.fail,
    onApplied: async () => {},
  }, elements, state);

  assert.equal(feedback.textContent, "守卫已关闭，已立即尝试恢复受影响凭证的原路由状态");
  assert.equal(feedback.dataset.state, "success");
  assert.deepEqual(toasts, ["429 守卫已关闭，并已立即尝试恢复原路由状态"]);
});

test("rejects invalid guard actions", () => {
  assert.throws(() => createSettingsPayload({
    auto_429_enabled: true,
    action: "pause",
    temporary_priority: 13,
    consecutive_429_threshold: 3,
  }), /请选择 429 处理方式/);
});

test("rejects empty and non-integer priorities", () => {
  for (const temporaryPriority of ["", "12.5", Number.POSITIVE_INFINITY]) {
    assert.throws(() => createSettingsPayload({
      auto_429_enabled: true,
      action: "disable",
      temporary_priority: temporaryPriority,
      consecutive_429_threshold: 3,
    }), /优先级必须是整数/);
  }
});

test("rejects invalid consecutive 429 thresholds", () => {
  for (const threshold of ["", 0, -1, "2.5", Number.POSITIVE_INFINITY]) {
    assert.throws(() => createSettingsPayload({
      auto_429_enabled: true,
      action: "disable",
      temporary_priority: 13,
      consecutive_429_threshold: threshold,
    }), /连续 429 触发次数必须是大于或等于 1 的整数/);
  }
});

test("disables the threshold only when the guard is unavailable or switched off", () => {
  const elements = {
    auto429: { checked: true, disabled: false },
    actionGroup: { disabled: false },
    priority: { disabled: false },
    prioritySetting: { dataset: {} },
    threshold: { disabled: false },
    thresholdSetting: { dataset: {} },
    submit: { disabled: false, textContent: "" },
    form: {
      querySelector(selector) {
        if (selector.endsWith(":checked")) return { value: "priority" };
        return null;
      },
    },
  };
  const state = { globalBusy: false, busy: false, initialized: true };

  renderControlState(elements, state);
  assert.equal(elements.threshold.disabled, false);
  assert.equal(elements.thresholdSetting.dataset.disabled, "false");

  elements.auto429.checked = false;
  renderControlState(elements, state);
  assert.equal(elements.threshold.disabled, true);
  assert.equal(elements.thresholdSetting.dataset.disabled, "true");

  elements.auto429.checked = true;
  state.globalBusy = true;
  renderControlState(elements, state);
  assert.equal(elements.threshold.disabled, true);
});

test("keeps the specified priority editable for both guard strategies", () => {
  let action = "disable";
  const elements = {
    auto429: { checked: true, disabled: false },
    actionGroup: { disabled: false },
    priority: { disabled: false },
    prioritySetting: { dataset: {} },
    threshold: { disabled: false },
    thresholdSetting: { dataset: {} },
    submit: { disabled: false, textContent: "" },
    form: {
      querySelector(selector) {
        if (selector.endsWith(":checked")) return { value: action };
        return null;
      },
    },
  };
  const state = { globalBusy: false, busy: false, initialized: true };

  renderControlState(elements, state);
  assert.equal(elements.priority.disabled, false);
  assert.equal(elements.prioritySetting.dataset.disabled, "false");

  action = "priority";
  renderControlState(elements, state);
  assert.equal(elements.priority.disabled, false);

  elements.auto429.checked = false;
  renderControlState(elements, state);
  assert.equal(elements.priority.disabled, true);
  assert.equal(elements.prioritySetting.dataset.disabled, "true");
});
