"use strict";

(() => {
  const defaultSettings = Object.freeze({
    auto_429_enabled: true,
    action: "disable",
    temporary_priority: 13,
    consecutive_429_threshold: 3,
  });

  function normalizeConfiguration(configuration) {
    const source = configuration && typeof configuration === "object" ? configuration : {};
    const priority = Number(source.temporary_priority);
    const threshold = Number(source.consecutive_429_threshold);
    return {
      auto_429_enabled: source.auto_429_enabled !== false,
      action: source.action === "priority" ? "priority" : "disable",
      temporary_priority: Number.isSafeInteger(priority) ? priority : defaultSettings.temporary_priority,
      consecutive_429_threshold: Number.isSafeInteger(threshold) && threshold >= 1
        ? threshold
        : defaultSettings.consecutive_429_threshold,
    };
  }

  function integerValue(value) {
    const raw = typeof value === "string" ? value.trim() : value;
    return raw === "" ? Number.NaN : Number(raw);
  }

  function createSettingsPayload(values) {
    if (typeof values?.auto_429_enabled !== "boolean") {
      throw new Error("自动守卫状态无效");
    }
    if (values.action !== "disable" && values.action !== "priority") {
      throw new Error("请选择 429 处理方式");
    }

    const priority = integerValue(values.temporary_priority);
    if (!Number.isSafeInteger(priority)) {
      throw new Error("指定优先级必须是整数");
    }
    const threshold = integerValue(values.consecutive_429_threshold);
    if (!Number.isSafeInteger(threshold) || threshold < 1) {
      throw new Error("连续 429 触发次数必须是大于或等于 1 的整数");
    }

    return {
      auto_429_enabled: values.auto_429_enabled,
      action: values.action,
      temporary_priority: priority,
      consecutive_429_threshold: threshold,
    };
  }

  function postSettings(request, payload) {
    return request("/settings", { method: "POST", body: JSON.stringify(payload) });
  }

  function cleanupNotice(cleanup) {
    const failed = Object.keys(cleanup?.failed || {}).length;
    if (!failed) return "";
    return `守卫已关闭，但有 ${failed} 个凭证恢复失败，正在重试。`;
  }

  function successNotice(auto429Enabled) {
    if (auto429Enabled) {
      return {
        feedback: "已应用，将用于后续新触发的 429",
        toast: "429 守卫策略已应用，仅当前进程生效",
      };
    }
    return {
      feedback: "守卫已关闭，已立即尝试恢复受影响凭证的原路由状态",
      toast: "429 守卫已关闭，并已立即尝试恢复原路由状态",
    };
  }

  function settingsElements() {
    return {
      form: document.querySelector("#guardSettingsForm"),
      auto429: document.querySelector("#auto429Enabled"),
      actionGroup: document.querySelector("#guardActionGroup"),
      priority: document.querySelector("#temporaryPriority"),
      prioritySetting: document.querySelector("#prioritySetting"),
      threshold: document.querySelector("#consecutive429Threshold"),
      thresholdSetting: document.querySelector("#thresholdSetting"),
      submit: document.querySelector("#applyGuardSettings"),
      feedback: document.querySelector("#guardSettingsFeedback"),
    };
  }

  function selectedAction(elements) {
    return elements.form.querySelector('input[name="guardAction"]:checked')?.value || "";
  }

  function renderControlState(elements, state) {
    const enabled = elements.auto429.checked;
    const unavailable = state.globalBusy || state.busy || !state.initialized;
    elements.auto429.disabled = unavailable;
    elements.actionGroup.disabled = unavailable || !enabled;
    elements.priority.disabled = unavailable || !enabled;
    elements.threshold.disabled = unavailable || !enabled;
    elements.prioritySetting.dataset.disabled = String(!enabled);
    elements.thresholdSetting.dataset.disabled = String(!enabled);
    elements.submit.disabled = unavailable;
    elements.submit.textContent = state.busy ? "应用中…" : "应用策略";
  }

  function setFeedback(elements, message, status = "") {
    elements.feedback.textContent = message;
    if (status) elements.feedback.dataset.state = status;
    else delete elements.feedback.dataset.state;
  }

  function renderSettings(elements, state, nextConfiguration, forceSync = false) {
    state.configuration = normalizeConfiguration(nextConfiguration);
    if (forceSync || !state.initialized || !state.dirty) {
      elements.auto429.checked = state.configuration.auto_429_enabled;
      const action = elements.form.querySelector(`input[name="guardAction"][value="${state.configuration.action}"]`);
      if (action) action.checked = true;
      elements.priority.value = String(state.configuration.temporary_priority);
      elements.threshold.value = String(state.configuration.consecutive_429_threshold);
      state.initialized = true;
    }
    renderControlState(elements, state);
  }

  function readSettingsPayload(elements) {
    return createSettingsPayload({
      auto_429_enabled: elements.auto429.checked,
      action: selectedAction(elements),
      temporary_priority: elements.priority.value,
      consecutive_429_threshold: elements.threshold.value,
    });
  }

  async function applySettings(dependencies, elements, state) {
    let payload;
    try {
      payload = readSettingsPayload(elements);
    } catch (error) {
      setFeedback(elements, error.message, "error");
      dependencies.showToast(error.message, true);
      return;
    }
    state.busy = true;
    renderControlState(elements, state);
    setFeedback(elements, "正在应用…");
    try {
      const result = await postSettings(dependencies.request, payload);
      state.configuration = { ...state.configuration, ...(result?.configuration || result) };
      state.dirty = false;
      if (typeof dependencies.onApplied === "function") await dependencies.onApplied(state.configuration);
      renderSettings(elements, state, state.configuration, true);
      const cleanupWarning = cleanupNotice(result?.cleanup);
      if (cleanupWarning) {
        setFeedback(elements, cleanupWarning, "warning");
        dependencies.showToast(cleanupWarning, true);
      } else {
        const notice = successNotice(payload.auto_429_enabled);
        setFeedback(elements, notice.feedback, "success");
        dependencies.showToast(notice.toast);
      }
    } catch (error) {
      setFeedback(elements, error.message || "策略应用失败", "error");
      dependencies.handleError(error);
    } finally {
      state.busy = false;
      renderControlState(elements, state);
    }
  }

  function createSettingsController(dependencies) {
    const elements = settingsElements();
    const state = {
      configuration: defaultSettings,
      globalBusy: false,
      busy: false,
      dirty: false,
      initialized: false,
    };
    const render = (configuration, forceSync) => renderSettings(elements, state, configuration, forceSync);
    const markDirty = () => {
      state.dirty = true;
      setFeedback(elements, "");
      renderControlState(elements, state);
    };
    elements.form.addEventListener("submit", (event) => {
      event.preventDefault();
      applySettings(dependencies, elements, state);
    });
    elements.auto429.addEventListener("change", markDirty);
    elements.actionGroup.addEventListener("change", markDirty);
    elements.priority.addEventListener("input", markDirty);
    elements.threshold.addEventListener("input", markDirty);
    renderControlState(elements, state);
    return {
      render,
      setGlobalBusy(value) {
        state.globalBusy = Boolean(value);
        renderControlState(elements, state);
      },
      isBusy() {
        return state.globalBusy || state.busy;
      },
    };
  }

  globalThis.GuardSettings = {
    normalizeConfiguration,
    createSettingsPayload,
    postSettings,
    cleanupNotice,
    successNotice,
    renderControlState,
    applySettings,
    createSettingsController,
  };
})();
