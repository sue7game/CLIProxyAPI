"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

require("./format.js");
require("./proxy.js");
require("./credentials.js");
const source = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");

function appFixture(status = 502) {
  const elements = new Map();
  const calls = [];
  const intervals = [];
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      hidden: false, value: "", dataset: {}, textContent: "", innerHTML: "",
      addEventListener() {}, classList: { toggle() {} }, querySelectorAll: () => [],
    });
    return elements.get(id);
  };
  const data = {
    generated_at: "2026-10-24T12:00:00Z", configuration: {}, proxy_groups: [],
    credentials: [{ auth_index: "ag-1", name: "test.json", configured_priority: 14, effective_priority: 14, usage: {}, subscription: { found: true, plan: "pro" } }],
  };
  const controller = () => ({ render() {}, setGlobalBusy() {}, isBusy: () => false, matches: () => true });
  const context = vm.createContext({
    document: { hidden: false, querySelector: element, getElementById: element, addEventListener() {}, querySelectorAll: () => [] },
    setInterval(callback, delay) { intervals.push({ callback, delay }); }, setTimeout() {}, clearTimeout() {},
    GuardView: globalThis.GuardView, GuardCredentials: globalThis.GuardCredentials,
    GuardProxy: { ...globalThis.GuardProxy, createProxyController: controller },
    GuardSettings: { createSettingsController: controller }, GuardCodex: { createCodexController: controller },
    GuardSearch: { matchesCredential: () => true },
    GuardAPI: {
      managementKey: () => "", saveManagementKey() {}, clearManagementKey() {},
      async request(route) {
        calls.push(route);
        if (route === "/quota/refresh") throw Object.assign(new Error("quota failed"), { status });
        return data;
      },
    },
  });
  vm.runInContext(source, context);
  context.fixture = data;
  vm.runInContext("state.data = fixture", context);
  return { context, calls, intervals, elements };
}

test("quota failure reloads cached state so successful subscription becomes visible", async () => {
  const { context, calls, elements } = appFixture();
  await context.credentialAction("quota", "ag-1");
  assert.deepEqual(calls, ["/quota/refresh", "/state"]);
  assert.match(elements.get("#credentialsBody").innerHTML, /订阅 · Pro/);
  assert.equal(elements.get("#toast").textContent, "quota failed");
});

test("authorization failures do not trigger an extra cached-state request", async () => {
  for (const status of [401, 403]) {
    const { context, calls } = appFixture(status);
    await context.credentialAction("quota", "ag-1");
    assert.deepEqual(calls, ["/quota/refresh"]);
  }
});

test("30-second auto refresh only fetches cached state", async () => {
  const { calls, intervals } = appFixture();
  const poll = intervals.find((interval) => interval.delay === 30000);
  assert.ok(poll);
  await poll.callback();
  assert.deepEqual(calls, ["/state"]);
});
