"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

require("./bulk-quota.js");

test("fetches selected quotas serially and continues after a failure", async () => {
  const calls = [];
  let active = 0;
  let maxActive = 0;
  const button = { disabled: false, textContent: "" };
  const progress = { textContent: "" };
  const toasts = [];
  const busyStates = [];
  let reloaded = 0;
  const controller = globalThis.GuardBulkQuota.createBulkQuotaController({
    button,
    progress,
    intervalMs: 1,
    wait: async () => {},
    async request(path, options) {
      active += 1;
      maxActive = Math.max(maxActive, active);
      const authIndex = JSON.parse(options.body).auth_index;
      calls.push([path, authIndex]);
      await Promise.resolve();
      active -= 1;
      if (authIndex === "auth-2") throw new Error("quota failed");
    },
    showToast: (...args) => toasts.push(args),
    handleError: (error) => { throw error; },
    reloadState: async () => { reloaded += 1; },
    setGlobalBusy: (value) => busyStates.push(value),
  });

  await controller.start(["auth-1", "auth-2", "auth-3", "auth-1"]);

  assert.deepEqual(calls, [["/quota", "auth-1"], ["/quota", "auth-2"], ["/quota", "auth-3"]]);
  assert.equal(maxActive, 1);
  assert.equal(reloaded, 1);
  assert.deepEqual(busyStates, [true, false]);
  assert.match(toasts[0][0], /成功 2 个，失败 1 个/);
  assert.equal(toasts[0][1], true);
  assert.equal(progress.textContent, "");
  assert.equal(controller.isBusy(), false);
});
