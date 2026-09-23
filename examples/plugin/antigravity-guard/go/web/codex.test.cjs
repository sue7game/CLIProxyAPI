"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

require("./codex.js");

test("renders manual recovery for every Codex credential", () => {
  const body = { innerHTML: "", addEventListener() {} };
  const empty = { hidden: false };
  const controller = globalThis.GuardCodex.createCodexController({
    body,
    empty,
    request: async () => ({}),
    showToast() {},
    handleError() {},
    reloadState: async () => {},
    credentials: () => [],
    esc: String,
    sortCredentials: (items) => items,
    busyAuth: new Set(),
  });

  controller.render([
    { auth_index: "enabled", name: "enabled.json", effective_disabled: false, codex: { status: "正常" } },
    { auth_index: "disabled", name: "disabled.json", effective_disabled: true, codex: { status: "401 已禁用" } },
  ]);

  assert.equal((body.innerHTML.match(/data-action="manual-recover"/g) || []).length, 2);
  assert.match(body.innerHTML, />启用</);
  assert.match(body.innerHTML, />已禁用</);
  assert.equal(empty.hidden, true);
});

test("manual recovery calls the recovery endpoint", async () => {
  const calls = [];
  const body = { innerHTML: "", addEventListener() {} };
  const controller = globalThis.GuardCodex.createCodexController({
    body,
    empty: null,
    request: async (path, options) => calls.push([path, options]),
    showToast() {},
    handleError(error) { throw error; },
    reloadState: async () => {},
    credentials: () => [],
    esc: String,
    sortCredentials: (items) => items,
    busyAuth: new Set(),
  });

  await controller.recover("codex-1");

  assert.deepEqual(calls, [["/recover", { method: "POST", body: JSON.stringify({ auth_index: "codex-1" }) }]]);
});
