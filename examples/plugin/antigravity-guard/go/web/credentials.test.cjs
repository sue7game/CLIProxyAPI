"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

require("./format.js");
require("./proxy.js");
require("./credentials.js");
const { renderSubscription, renderCredentialRow } = globalThis.GuardCredentials;

test("renders every known subscription plan", () => {
  for (const [plan, label] of Object.entries({ free: "Free", pro: "Pro", ultra: "Ultra", "ultra-lite": "Ultra Lite" })) {
    const html = renderSubscription({ found: true, plan, tier_name: label, updated_at: "2026-10-24T12:00:00Z" });
    assert.ok(html.includes(`订阅 · ${label}`));
    assert.match(html, /获取于/);
    assert.doesNotMatch(html, /失败|未获取/);
  }
});

test("unknown plans retain the upstream name or id instead of showing Free", () => {
  assert.match(renderSubscription({ found: true, plan: "unknown", tier_name: "Enterprise" }), /未知套餐 · Enterprise/);
  assert.match(renderSubscription({ found: true, plan: "future", tier_id: "new-tier" }), /未知套餐 · new-tier/);
  assert.doesNotMatch(renderSubscription({ found: true, plan: "unknown" }), /Free/);
});

test("distinguishes unqueried, initial failure and stale successful data", () => {
  assert.match(renderSubscription(), /订阅未获取/);
  assert.match(renderSubscription({ found: false }), /订阅未获取/);
  const failure = renderSubscription({ found: false, last_error: "HTTP 403" });
  assert.match(failure, /订阅查询失败/);
  assert.match(failure, /title="HTTP 403"/);
  assert.match(failure, /tabindex="0"/);
  assert.doesNotMatch(failure, /Free|订阅未获取/);
  const stale = renderSubscription({ found: true, plan: "pro", last_error: "network failed" });
  assert.match(stale, /订阅 · Pro/);
  assert.match(stale, /更新失败 · 保留上次结果/);
});

test("escapes upstream tier names, ids and errors", () => {
  const html = renderSubscription({
    found: true, plan: "unknown", tier_id: '"><script>bad()</script>',
    tier_name: '<img src=x onerror="bad()">', last_error: '"><svg onload="bad()">',
  });
  assert.doesNotMatch(html, /<script>|<img|<svg/);
  assert.match(html, /&lt;img/);
  assert.match(html, /&quot;/);
  assert.match(html, /&lt;svg/);
});

function rowFixture(overrides = {}, busy = false) {
  const item = {
    auth_index: "ag-1", name: "test.json", configured_priority: 14, effective_priority: 14,
    effective_proxy: "socks5h://proxy.invalid:1080", proxy_alias: "测试代理", usage: {},
    subscription: { found: true, plan: "ultra-lite" }, ...overrides,
  };
  const context = {
    busyAuth: new Set(busy ? [item.auth_index] : []), selected: new Set([item.auth_index]),
    proxyChoices: new Map(), credentials: [item], configuration: {}, loadedAt: 0,
  };
  return renderCredentialRow(item, context);
}

test("subscription stays inside the identity cell and preserves existing actions", () => {
  const html = rowFixture();
  assert.equal((html.match(/<td[ >]/g) || []).length, 8);
  assert.match(html, /credential-name[^]*订阅 · Ultra Lite/);
  assert.match(html, /data-action="quota"/);
  assert.match(html, /data-action="manual-recover"/);
  assert.match(html, /data-action="apply-proxy-choice"/);
  assert.match(html, /row-select[^]*checked/);
  assert.match(html, />测试代理</);
});

test("quota loading feedback and disabled controls are preserved", () => {
  const html = rowFixture({}, true);
  assert.match(html, /data-action="quota"[^>]*disabled>获取中/);
  assert.match(html, /proxy-choice[^>]*disabled/);
});

test("credential identity and subscription content are escaped independently", () => {
  const html = rowFixture({ name: '<script>alert("x")</script>', subscription: { found: true, tier_name: "<b>Custom</b>" } });
  assert.doesNotMatch(html, /<script>|<b>/);
  assert.match(html, /&lt;script/);
  assert.match(html, /&lt;b&gt;Custom/);
});
